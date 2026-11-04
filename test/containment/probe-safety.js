// Probe safety: make an escape probe demonstrate reach without being an attack.
//
// Single shared copy. Both payloads require this file; it is deliberately NOT
// duplicated per fixture, because a fix applied to one copy and not the other
// silently leaves the other payload running the old guard.
//
// On the UNPATCHED build a "successful" probe really executes on the user's
// Mac. That is the point of the unpatched run, and also the risk: the probe set
// is a working exploit chain against the machine it is validated on. So every
// payload is inert by construction and this module enforces it.
//
// Rules are in rpc-filter/AGENTS.md section 8. The design rule that drives this
// file: NOTHING that determines a target may come from the workspace or from
// the tab's environment. The tab is hostile by assumption, and both
// .seclab/targets and the REH's environment are inside its control. Everything
// is derived from one trusted input, SECLAB_PROBE_RUNDIR, which only the
// harness sets on the trusted side.
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

// Fixed names inside the run directory. Not configurable, so a hostile
// workspace cannot steer any probe at a path of its choosing.
const MARKER_BASENAME = 'PWNED';
const CANARY_BASENAME = 'canary.txt';
const NONCE_FILE = '.seclab-probe-nonce';

// Conservative path charset. A probe needs nothing else, and this is what stops
// a quote or a shell metacharacter reaching a command string.
const SAFE_PATH_CHARS = /^[A-Za-z0-9._\/-]+$/;

/** Real user data a probe must never touch, whatever the path shape. */
const FORBIDDEN = [
	/\/\.ssh(\/|$)/i, /\/\.aws(\/|$)/i, /\/\.gnupg(\/|$)/i, /\/\.config\/gh(\/|$)/i,
	/\/\.kube(\/|$)/i, /\/\.docker(\/|$)/i, /\/\.netrc$/i, /\/\.git-credentials$/i,
	/Library\/Keychains/i, /Library\/LaunchAgents/i, /Library\/LaunchDaemons/i,
	/Library\/Application Support\/(Code|Google|Firefox)/i, /Library\/Cookies/i,
	/\/\.(bashrc|zshrc|bash_profile|zprofile|profile)$/i,
	/\/etc\/(passwd|shadow|sudoers)/i,
];

/**
 * Arming requires a run directory supplied by the HARNESS -- never a fallback
 * to workspace-supplied data -- plus a nonce that matches a file inside it.
 */
function arm(armingFile) {
	// Two delivery routes, because the two fixtures live on opposite sides of
	// the boundary:
	//
	//  * Host side (and the REH payload): the environment. Trusted, because
	//    only the harness sets it.
	//  * Inside the tab: a file the harness wrote into the workspace. The tab
	//    gets `env -i` (sandbox/rootfs/opt/seclab/bin/seclab-tab-env), so no
	//    host environment reaches an extension -- by design.
	//
	// The in-tab route is weaker: the workspace is attacker-writable, so a
	// hostile workspace could self-arm. That is accepted. Arming exists to stop
	// this extension doing anything if it is installed somewhere that is not a
	// harness run; it is not a containment boundary. The real boundary is
	// enforced host-side by the teardown tripwire and the beacon.
	let nonce = process.env.SECLAB_PROBE_NONCE;
	let runDir = process.env.SECLAB_PROBE_RUNDIR;
	let advisory = false;
	if ((!nonce || !runDir) && armingFile) {
		try {
			const a = JSON.parse(fs.readFileSync(armingFile, 'utf8'));
			nonce = a.nonce;
			runDir = a.runDir;
			advisory = true;
		} catch { /* fall through to unarmed */ }
	}
	if (!nonce || !runDir) {
		return { armed: false, reason: 'no arming nonce / run directory from the harness' };
	}
	// The run directory is a HOST path. Inside the tab it is not mounted, so it
	// cannot be stat-ed and containment has to be lexical. Say so explicitly
	// rather than silently weakening the check.
	let root = path.resolve(runDir);
	let lexicalOnly = true;
	try {
		root = fs.realpathSync(runDir);
		const onDisk = fs.readFileSync(path.join(root, NONCE_FILE), 'utf8').trim();
		if (onDisk !== nonce) {
			return { armed: false, reason: 'nonce mismatch' };
		}
		lexicalOnly = false;
	} catch {
		if (!advisory) {
			return { armed: false, reason: 'run directory or nonce file not readable' };
		}
	}
	return { armed: true, runDir: root, lexicalOnly, advisory };
}

/**
 * Every filesystem target a probe names must sit inside the run directory.
 *
 * Three separate checks, because each catches what the others miss:
 *   - a charset check, so no quote or shell metacharacter can ever reach a
 *     command string built from a path;
 *   - a pattern check for known real-user locations;
 *   - containment, verified on the symlink-resolved location, with the final
 *     component rejected if it is itself a link. A *dangling* symlink would
 *     otherwise make realpath throw, the loop fall back to the parent, and the
 *     lexical path be returned and then followed by the write.
 */
function safePath(ctx, p, what) {
	if (typeof p !== 'string' || !p) {
		throw new SafetyError(`${what}: empty path`);
	}
	if (!SAFE_PATH_CHARS.test(p)) {
		throw new SafetyError(`${what}: path contains characters a probe may not use (${p})`);
	}
	for (const bad of FORBIDDEN) {
		if (bad.test(p)) {
			throw new SafetyError(`${what}: refuses to touch real user data (${p})`);
		}
	}
	const resolved = path.resolve(p);
	const root = ctx.runDir;
	if (ctx.lexicalOnly) {
		// Inside the tab the target is a host path we cannot stat. Charset and
		// FORBIDDEN have already run; all that is left is a strict prefix test.
		// Advisory, as recorded in arm().
		if (resolved !== root && !resolved.startsWith(root + path.sep)) {
			throw new SafetyError(`${what}: ${resolved} is outside ${root}`);
		}
		return resolved;
	}
	const parent = path.dirname(resolved);
	let realParent;
	try {
		realParent = fs.realpathSync(parent);
	} catch (err) {
		throw new SafetyError(`${what}: parent does not resolve: ${err.message}`);
	}
	const inside = (q) => q === root || q.startsWith(root + path.sep);
	if (!inside(realParent)) {
		throw new SafetyError(`${what}: ${resolved} is under ${realParent}, outside ${root}`);
	}
	// The final component must not be a symlink of any kind, dangling included.
	const verified = path.join(realParent, path.basename(resolved));
	try {
		if (fs.lstatSync(verified).isSymbolicLink()) {
			throw new SafetyError(`${what}: ${verified} is a symlink`);
		}
	} catch (err) {
		if (err && err.seclabSafety) { throw err; }
		// ENOENT is fine: the probe is about to create it.
	}
	return verified;
}

/** The only network destination any probe may name. */
function safeUrl(ctx, url, what) {
	const s = String(url);
	const m = /^http:\/\/127\.0\.0\.1:(\d+)(\/[A-Za-z0-9._\/-]*)?$/.exec(s);
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
 * marker file inside the run directory.
 *
 * The path is derived from the run directory and a fixed basename, never from
 * workspace or environment data, and safePath() has already rejected every
 * character that could terminate the quoting. Terminal probes have no other way
 * to show they reached a host shell.
 */
function markerCommand(ctx, suffix) {
	const name = MARKER_BASENAME + (suffix || '');
	if (!/^[A-Za-z0-9._-]+$/.test(name)) {
		throw new SafetyError(`marker: bad suffix ${suffix}`);
	}
	const target = safePath(ctx, path.join(ctx.runDir, name), 'marker');
	return `touch '${target}'\n`;
}

/** A path inside the run directory, by fixed name. */
function runPath(ctx, name, what) {
	if (!/^[A-Za-z0-9._-]+$/.test(name)) {
		throw new SafetyError(`${what}: bad name ${name}`);
	}
	return safePath(ctx, path.join(ctx.runDir, name), what);
}

/** Record what the run created so teardown can assert it cleaned up. */
function note(ctx, artefact) {
	ctx.artefacts.push(artefact);
	try {
		fs.appendFileSync(path.join(ctx.runDir, 'probe-artefacts.txt'), `${artefact}\n`);
	} catch { /* best effort */ }
}

function context(armingFile) {
	const armed = arm(armingFile);
	if (!armed.armed) {
		return { armed: false, reason: armed.reason };
	}
	const ctx = {
		armed: true,
		runDir: armed.runDir,
		lexicalOnly: armed.lexicalOnly,
		advisory: armed.advisory,
		beaconPort: process.env.SECLAB_PROBE_BEACON_PORT
			? Number(process.env.SECLAB_PROBE_BEACON_PORT) : null,
		artefacts: [],
		// Per-run so teardown can delete exactly what this run created.
		secretKey: `seclab-probe-${(process.env.SECLAB_PROBE_NONCE || 'run').slice(0, 16)}`,
	};
	ctx.marker = path.join(ctx.runDir, MARKER_BASENAME);
	ctx.canary = path.join(ctx.runDir, CANARY_BASENAME);
	return ctx;
}

module.exports = {
	SafetyError, context, safePath, safeUrl, markerCommand, runPath, note,
	FORBIDDEN, MARKER_BASENAME, CANARY_BASENAME, NONCE_FILE,
};
