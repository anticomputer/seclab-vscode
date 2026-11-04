#!/usr/bin/python3 -I
# Regression check for the sbx observability guard (security review OR-1, OR-2). The harness
# runs it as the tab user under seclab-obs-guard. Prints one JSON line; changes nothing.
import ctypes, json, os

libc = ctypes.CDLL(None, use_errno=True)
NR = {"seccomp": 277, "io_uring_setup": 425, "clone": 220}
if os.uname().machine == "x86_64":
    NR = {"seccomp": 317, "io_uring_setup": 425, "clone": 56}


class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]


class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]


def errno_of(r):
    return "ok" if r >= 0 else os.strerror(ctypes.get_errno())


def clone_untraced():
    r = libc.syscall(NR["clone"], 0x00800000 | 17, 0, 0, 0, 0)
    if r == 0:
        os._exit(0)  # the child (only if the guard failed): leave quietly
    if r > 0:
        os.waitpid(r, 0)
    return errno_of(r)


# A one-instruction filter: return SECCOMP_RET_ALLOW. Asking for a listener must be refused.
# Set no_new_privs first, as an attacker would (any process may), so the control run is real.
libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS
allow = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0x7fff0000))
prog = SockFprog(1, allow)
SECCOMP_SET_MODE_FILTER, NEW_LISTENER = 1, 1 << 3
def stray_fds():
    # fds above 2 that are still open (listdir's own directory fd is gone by the time we look).
    out = []
    for f in os.listdir("/proc/self/fd"):
        try:
            os.readlink("/proc/self/fd/" + f)
        except OSError:
            continue
        if int(f) > 2:
            out.append(int(f))
    return sorted(out)


out = {
    "seccompListener": errno_of(libc.syscall(NR["seccomp"], SECCOMP_SET_MODE_FILTER, NEW_LISTENER, ctypes.byref(prog))),
    "ioUringSetup": errno_of(libc.syscall(NR["io_uring_setup"], 1, None)),
    "cloneUntraced": clone_untraced(),
    "fds": stray_fds(),
    "uid": os.getuid(),
}
print(json.dumps(out))
