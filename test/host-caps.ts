// Host capabilities a test can need but must never ask the operator for. A test that needs one
// skips with the reason unless the host declares it:
//   SECLAB_HOST_CAPS=keystrokes,screen-capture
// Declare one only on a host where it is already available and expendable (a disposable VM or CI
// runner), never by granting it for a run. Nothing here checks or requests an OS permission.

export const HOST_CAPS = {
	'keystrokes': 'sends keystrokes to the window server (macOS: System Events, needs Accessibility)',
	'screen-capture': 'captures window contents (macOS: screencapture, needs Screen Recording)',
} as const;
export type HostCap = keyof typeof HOST_CAPS;

export function hostCaps(): Set<string> {
	return new Set((process.env.SECLAB_HOST_CAPS ?? '').split(',').map(s => s.trim()).filter(Boolean));
}

export function hasHostCap(cap: HostCap): boolean {
	return hostCaps().has(cap);
}

export function skipReason(cap: HostCap, what: string): string {
	return `SKIPPED ${what}: needs the "${cap}" host capability (${HOST_CAPS[cap]}). Set SECLAB_HOST_CAPS only on a host that already has it to spare.`;
}

/** Exits 0 with a SKIPPED line unless the host declares `cap`. */
export function requireHostCap(cap: HostCap, what: string): void {
	if (!hasHostCap(cap)) {
		console.log(skipReason(cap, what));
		process.exit(0);
	}
}
