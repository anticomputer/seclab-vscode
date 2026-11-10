// How the probe runner spawns its detached helpers, and the teardown marks that must match
// them. This lives apart from runner.ts so the unit tests can assert the two agree: a mark
// that teardown would reject has twice now survived review and failed only in a live run
// (security review rounds 2 and 3).
//
// Teardown's rules, from test/containment/teardown.ts:
//   - a mark must appear in the process argv with whitespace or a line edge on each side, so
//     it has to be a run of whole argv tokens;
//   - a mark must contain the run directory followed by a separator, or end with it. One mark
//     that breaks this makes the whole teardown gate refuse to act.

import * as path from 'node:path';

export interface HelperSpawn { readonly argv: string[]; readonly mark: string }

/** The mark for an argv: the whole command line, so the two can never drift apart. */
export function markFor(argv: readonly string[]): string {
	return argv.join(' ');
}

export function beaconSpawn(repoRoot: string, beaconLog: string, port: number, bind?: string): HelperSpawn {
	const argv = [path.join(repoRoot, 'test', 'containment', 'beacon.ts'), 'start', beaconLog, String(port), ...(bind ? [bind] : [])];
	return { argv, mark: markFor(argv) };
}

/** `--run-dir` is last so the mark ends with the run directory (teardown rule R-1). */
export function armSpawn(runnerScript: string, userData: string, driver: string, base: string): HelperSpawn {
	const argv = [runnerScript, 'arm', userData, '--driver', driver, '--user-data-dir', userData, '--run-dir', base];
	return { argv, mark: markFor(argv) };
}
