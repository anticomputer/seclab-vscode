// Probe safety: make an escape probe demonstrate reach without being an attack.
//
// On the UNPATCHED build a "successful" probe really executes on the user's
// Mac. That is the point of the unpatched run, and it is also the risk: the
// probe set is a working exploit chain against the machine it is validated on.
// So every payload is inert by construction, and this module is what enforces
// it rather than leaving it to each probe's good intentions.
//
// Rules (also in rpc-filter/AGENTS.md; a CI lint checks the sources):
//
//   1. Success only demonstrates REACH. Host code execution means writing one
//      fixed marker file under the run directory. No shells beyond that, no
//      downloads, no persistence, no deletes, no settings changes.
//   2. Reads touch only harness-seeded canaries, never real user paths.
//   3. Fake credentials only, in the isolated user-data-dir.
//   4. Network only to the harness's local beacon on 127.0.0.1.
//   5. Extension/window probes act only on fixtures inside the run directory.
//   6. Arming: inert unless the harness supplies a per-run nonce in the
//      environment AND a matching file in the run directory. Installed
//      anywhere else, the extension does nothing.
//   7. Teardown removes everything; a post-run check verifies nothing outside
//      the run directory changed.
//
// A probe that asks for a target outside the run directory does not get a
// "denied" result -- it throws SafetyError, which the checker treats as a
// harness fault, never as containment.

'use strict';

const fs = require('fs');
const path = require('path');

class SafetyError extends Error {
	constructor(message) {
		super(`probe safety: ${message}`);
		this.name = 'SafetyError';
		this.seclabSafety = true;
	}
}

/**
 * Resolve the arming state. Both halves are required: an attacker who obtains
 * this extension cannot arm it by setting an environment variable alone,
 * because they would also need to write the nonce file into a run directory
 * the harness created.
 */
function arm(targets) {
	const nonce = process.env.SECLAB_PROBE_NONCE;
	const runDir = process.env.SECLAB_PROBE_RUNDIR || targets.rundir;
	if (!nonce || !runDir) {
		return { armed: false, reason: 'no SECLAB_PROBE_NONCE / run directory' };
	}
	let onDisk;
	try {
		onDisk = fs.readFileSync(path.join(runDir, '.seclab-probe-nonce'), 'utf8').trim();
	} catch {
		return { armed: false, reason: 'nonce file absent from the run directory' };
	}
	if (onDisk !== nonce) {
		return { armed: false, reason: 'nonce mismatch' };
	}
	return { armed: true, runDir: path.resolve(runDir), nonce };
}

/** Real user data that a probe must never touch, regardless of path shape. */
const FORBIDDEN = [
	/\/\.ssh(\/|$)/, /\/\.aws(\/|$)/, /\/\.gnupg(\/|$)/, /\/\.config\/gh(\/|$)/,
	/\/\.kube(\/|$)/, /\/\.docker(\/|$)/, /\/\.netrc$/, /\/\.git-credentials$/,
	/Library\/Keychains/, /Library\/Application Support\/(Code|Google|Firefox)/,
	/Library\/Cookies/, /\/etc\/(passwd|shadow|sudoers)/,
];

/**
 * Every filesystem target a probe names must sit inside the run directory.
 * Checked on the resolved real path, so `..` and symlinks cannot walk out.
 */
function safePath(ctx, p, what) {
	if (typeof p !== 'string' || !p) {
		throw new SafetyError(`${what}: empty path`);
	}
	for (const bad of FORBIDDEN) {
		if (bad.test(p)) {
			throw new SafetyError(`${what}: refuses to touch real user data (${p})`);
		}
	}
	const resolved = path.resolve(p);
	// Resolve symlinks on the nearest existing ancestor so a link out of the
	// run directory cannot smuggle the target past this check.
	let probe = resolved;
	for (;;) {
		try {
			probe = fs.realpathSync(probe);
			break;
		} catch {
			const parent = path.dirname(probe);
			if (parent === probe) { break; }
			probe = parent;
		}
	}
	const root = fs.realpathSync(ctx.runDir);
	const inside = (q) => q === root || q.startsWith(root + path.sep);
	// Only the symlink-resolved location counts. Accepting the lexically
	// resolved path as an alternative would defeat the check outright: a
	// symlink inside the run directory pointing anywhere on the host still
	// *looks* inside when compared lexically.
	if (!inside(probe)) {
		throw new SafetyError(`${what}: ${resolved} resolves to ${probe}, outside the run directory ${root}`);
	}
	return resolved;
}

/** The only network destination any probe may name. */
function safeUrl(ctx, url, what) {
	const s = String(url);
	const m = /^http:\/\/127\.0\.0\.1:(\d+)(\/|$)/.exec(s);
	if (!m) {
		throw new SafetyError(`${what}: only the local beacon is allowed, got ${s}`);
	}
	if (ctx.beaconPort && String(ctx.beaconPort) !== m[1]) {
		throw new SafetyError(`${what}: wrong port ${m[1]}, beacon is ${ctx.beaconPort}`);
	}
	return s;
}

/**
 * The single permitted demonstration of host code execution: create one fixed
 * marker file inside the run directory. Returned as a shell fragment because
 * terminal probes have no other way to show they reached a host shell.
 */
function markerCommand(ctx, suffix) {
	const target = safePath(ctx, `${ctx.marker}${suffix || ''}`, 'marker');
	// Single-quoted, and the path is already proven to be inside the run dir.
	return `touch '${target}'\n`;
}

/** Record what the run created so teardown can assert it cleaned up. */
function note(ctx, artefact) {
	ctx.artefacts.push(artefact);
	try {
		fs.appendFileSync(path.join(ctx.runDir, 'probe-artefacts.txt'), `${artefact}\n`);
	} catch { /* best effort */ }
}

function context(targets) {
	const armed = arm(targets);
	if (!armed.armed) {
		return { armed: false, reason: armed.reason };
	}
	return {
		armed: true,
		runDir: armed.runDir,
		marker: targets.marker,
		canary: targets.canary,
		beaconPort: targets.beacon ? Number(targets.beacon) : null,
		artefacts: [],
	};
}

module.exports = { SafetyError, context, safePath, safeUrl, markerCommand, note, FORBIDDEN };
