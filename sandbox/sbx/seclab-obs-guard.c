// seclab-obs-guard: run a command under a seccomp filter that keeps it observable.
// Usage (as root, under strace): seclab-obs-guard PROGRAM [ARG...]
//
// Under ptrace a tracee can create an untraced child with clone(CLONE_UNTRACED): the kernel
// skips the tracer's fork event (kernel/fork.c kernel_clone). That would let a tab escape the
// sbx observability collector. This filter, inherited by every descendant and irremovable:
//   - clone with CLONE_UNTRACED  -> EPERM
//   - clone3                     -> ENOSYS (its flags live in memory seccomp cannot read;
//                                   libc falls back to clone)
//   - seccomp(..NEW_LISTENER..)  -> EPERM: a user-notification filter outranks strace's
//                                   SECCOMP_RET_TRACE and lets syscalls run untraced
//                                   (security review OR-1)
//   - io_uring_*                 -> ENOSYS: io_uring ops never pass syscall tracing
//   - any foreign syscall ABI    -> kill (no 32-bit compat or x32 bypass)
// It also sets no_new_privs and closes every fd above 2 before exec, so the tab never holds
// the tracer's output pipe (review OR-2). See docs/adr/20261104-tab-observability.md §2.
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#if defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#elif defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#else
#error "unsupported architecture"
#endif

#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_close_range
#define __NR_close_range 436
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "usage: seclab-obs-guard PROGRAM [ARG...]\n");
		return 2;
	}
	struct sock_filter f[] = {
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 1, 0),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
		// x32 syscalls share the arch value; their numbers have bit 30 set.
		BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 2, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_enter, 1, 0),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_register, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_seccomp, 0, 4),
		// seccomp(op, flags, args): flags are args[1]; refuse any filter that wants a listener.
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, SECCOMP_FILTER_FLAG_NEW_LISTENER, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
		// clone flags are args[0]; CLONE_UNTRACED is in the low 32 bits (little-endian).
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
		BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_UNTRACED, 0, 1),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM),
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = { .len = sizeof(f) / sizeof(f[0]), .filter = f };
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
		perror("seclab-obs-guard: no_new_privs");
		return 126;
	}
	if (syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog) != 0) {
		perror("seclab-obs-guard: seccomp");
		return 126;
	}
	if (syscall(__NR_close_range, 3U, ~0U, 0U) != 0) {
		perror("seclab-obs-guard: close_range");
		return 126;
	}
	// fd 2 is strace's stderr pipe to the collector; the tab must not be able to write to it.
	int devnull = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (devnull < 0 || dup2(devnull, 2) != 2) {
		perror("seclab-obs-guard: stderr");
		return 126;
	}
	execv(argv[1], &argv[1]);
	return 127;
}
