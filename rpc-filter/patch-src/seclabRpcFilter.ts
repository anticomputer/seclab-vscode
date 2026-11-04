/*---------------------------------------------------------------------------------------------
 *  seclab-vscode: RPC capability filter.
 *
 *  Design and rationale: docs/RPC-LOCKDOWN.md. Policy table: rpc-filter/policy/policy.json.
 *
 *  A tab's sandbox contains the code it runs. It does not contain the tab's
 *  ability to ask the trusted side to act on its behalf, and the sandbox is
 *  pointless if the tab can ask the workbench to open a host terminal and type
 *  into it. This is the choke point that closes that.
 *--------------------------------------------------------------------------------------------*/

import { setSeclabChannelGuard } from '../../../../base/parts/ipc/common/ipc.js';
import { URI } from '../../../../base/common/uri.js';
import {
	SECLAB_CHANNELS, SECLAB_COMMANDS, SECLAB_DEFAULT_VERDICT, SECLAB_RPC,
	SECLAB_SERVICE_DEFAULTS, type SeclabEntry, type SeclabVerdict,
} from './seclabPolicyData.js';

/** Authorities we filter. Anything else is either local-trusted or unknown. */
const SECLAB_AUTHORITY = /^seclab\+/;

/** Upper bound on argument graph depth, matching `marshalling.revive`. */
const REVIVE_DEPTH_CAP = 200;

export interface SeclabDenial {
	readonly ref: string;
	readonly tabId: string;
	readonly reason: string;
	readonly at: number;
}

export interface ISeclabFilter {
	/** @returns an error to reject with, or undefined to let the call through. */
	checkRpc(sid: string, method: string, args: readonly unknown[]): Error | undefined;
	checkChannel(channel: string, method: string): Error | undefined;
	/** Verdict for a command id, used by $executeCommand and by the taint. */
	commandVerdict(id: string): SeclabVerdict;
	readonly tabId: string;
	readonly denials: readonly SeclabDenial[];
}

/**
 * The error a denied caller sees. Deliberately indistinguishable from an
 * unsupported operation: a tab should not be able to map the policy table by
 * probing it. The *host-side* denial log is how tests tell a denial from a
 * broken call -- see docs/security-reviews/20261104-rpc-probes-increment.md.
 */
function denied(): Error {
	return new Error('Unsupported operation');
}

/** Walk an argument graph the same way `revive` does, and reject what it cannot. */
function eachUri(value: unknown, depth: number, visit: (uri: URI) => string | undefined): string | undefined {
	if (depth > REVIVE_DEPTH_CAP) {
		// `revive` stops reviving past the cap, so a validator cannot agree with
		// the consumer beyond it. Refuse rather than guess.
		return 'argument graph deeper than the revive cap';
	}
	if (!value || typeof value !== 'object') {
		return undefined;
	}
	if (URI.isUri(value)) {
		return visit(value);
	}
	const obj = value as Record<string, unknown>;
	if (Object.prototype.hasOwnProperty.call(obj, '__proto__')) {
		return 'argument carries an own __proto__ property';
	}
	if (typeof obj['$mid'] === 'number' && typeof obj['scheme'] === 'string') {
		// A marshalled URI the consumer will revive.
		return visit(URI.revive(obj as never));
	}
	for (const key of Object.keys(obj)) {
		const reason = eachUri(obj[key], depth + 1, visit);
		if (reason) {
			return reason;
		}
	}
	return undefined;
}

class SeclabFilter implements ISeclabFilter {

	private readonly _denials: SeclabDenial[] = [];

	constructor(
		public readonly tabId: string,
		private readonly _authority: string,
		private readonly _onDenial?: (d: SeclabDenial) => void,
	) { }

	public get denials(): readonly SeclabDenial[] {
		return this._denials;
	}

	private _deny(ref: string, reason: string): Error {
		const record: SeclabDenial = { ref, tabId: this.tabId, reason, at: Date.now() };
		this._denials.push(record);
		this._onDenial?.(record);
		return denied();
	}

	private _entry(sid: string, method: string): SeclabEntry | undefined {
		return SECLAB_RPC.get(`${sid}.${method}`);
	}

	public checkRpc(sid: string, method: string, args: readonly unknown[]): Error | undefined {
		// `_doInvokeHandler` resolves `actor[methodName]` and only checks that it
		// is a function, so anything on the instance is reachable. The policy
		// table only describes `$` methods; everything else is refused outright
		// rather than falling through to a default.
		if (!method.startsWith('$')) {
			return this._deny(`rpc:${sid}.${method}`, 'not a $ method');
		}

		const entry = this._entry(sid, method);
		const verdict = entry?.verdict
			?? SECLAB_SERVICE_DEFAULTS.get(sid)
			?? SECLAB_DEFAULT_VERDICT;
		const ref = entry?.ref ?? `rpc:${sid}.${method}`;

		if (verdict === 'deny') {
			return this._deny(ref, 'policy');
		}
		if (verdict === 'allow' || verdict === 'rewrite') {
			// `rewrite` is applied by the customer itself (sentinel credential,
			// partitioned storage key); the call is permitted to reach it.
			return undefined;
		}
		if (verdict === 'prompt') {
			// Prompting is routed through the Tab Manager, which is not on this
			// synchronous path. Until that lands, prompt behaves as deny: the
			// closed direction.
			return this._deny(ref, 'prompt not yet wired; failing closed');
		}
		return this._constrain(sid, method, args, entry, ref);
	}

	private _constrain(
		sid: string, method: string, args: readonly unknown[],
		entry: SeclabEntry | undefined, ref: string,
	): Error | undefined {
		if (sid === 'MainThreadCommands' && method === '$executeCommand') {
			const id = args[0];
			if (typeof id !== 'string') {
				return this._deny(ref, 'command id is not a string');
			}
			const verdict = this.commandVerdict(id);
			if (verdict !== 'allow' && verdict !== 'allow_with_constraint') {
				return this._deny(`cmd:${id}`, 'command verdict ' + verdict);
			}
			return undefined;
		}

		if (sid === 'MainThreadFileSystem') {
			const reason = eachUri(args, 0, uri => this._checkUri(uri));
			return reason ? this._deny(ref, reason) : undefined;
		}

		// A constraint named in the table but not implemented here must not be
		// silently treated as satisfied.
		if (entry?.constraint) {
			return this._deny(ref, `constraint not implemented: ${entry.constraint}`);
		}
		return undefined;
	}

	/** This tab's own remote filesystem, or nothing. */
	private _checkUri(uri: URI): string | undefined {
		if (uri.scheme === 'untitled') {
			return undefined;
		}
		if (uri.scheme !== 'vscode-remote') {
			return `scheme ${uri.scheme} is not reachable from a tab`;
		}
		if (uri.authority !== this._authority) {
			return `authority ${uri.authority} is not this tab`;
		}
		return undefined;
	}

	public checkChannel(channel: string, method: string): Error | undefined {
		const entry = SECLAB_CHANNELS.get(channel);
		const verdict = entry?.verdict ?? SECLAB_DEFAULT_VERDICT;
		if (verdict === 'deny') {
			return this._deny(entry?.ref ?? `chan:${channel}`, `method ${method}`);
		}
		return undefined;
	}

	public commandVerdict(id: string): SeclabVerdict {
		return SECLAB_COMMANDS.get(id)?.verdict ?? SECLAB_DEFAULT_VERDICT;
	}
}

/**
 * Authority -> tab id, registered by the Tab Manager when it resolves an
 * authority. The filter's identity comes from here and never from anything the
 * tab sends: `MainThreadSecretState.$getPassword` takes the extension identity
 * as an *argument*, which is exactly the mistake this avoids repeating.
 */
const seclabTabs = new Map<string, string>();

export function seclabRegisterTab(authority: string, tabId: string): void {
	seclabTabs.set(authority, tabId);
}

export function seclabUnregisterTab(authority: string): void {
	seclabTabs.delete(authority);
}

export function seclabResolveTabId(authority: string): string | undefined {
	return seclabTabs.get(authority);
}

/**
 * Resolve the filter for an extension host, failing closed.
 *
 * `remoteAuthority` is `null` for local and worker hosts, so resolving by
 * authority alone is fail-open by shape: an unexpected value would yield "no
 * filter" rather than "deny everything". Instead:
 *
 *   - a `seclab+*` authority with no tab id is fatal;
 *   - a trusted local host (no authority) is unfiltered, by design;
 *   - anything else gets a deny-all filter.
 */
export function seclabFilterFor(
	remoteAuthority: string | null,
	resolveTabId: (authority: string) => string | undefined,
	onDenial?: (d: SeclabDenial) => void,
): ISeclabFilter | undefined {
	if (remoteAuthority === null) {
		return undefined;
	}
	if (!SECLAB_AUTHORITY.test(remoteAuthority)) {
		return new SeclabFilter('unknown', remoteAuthority, onDenial);
	}
	const tabId = resolveTabId(remoteAuthority);
	if (!tabId) {
		throw new Error(`seclab: no tab registered for authority ${remoteAuthority}`);
	}
	return new SeclabFilter(tabId, remoteAuthority, onDenial);
}

/**
 * Install the channel guard. Registering it here rather than from a workbench
 * contribution keeps the core diff to the two files this patch already touches.
 *
 * A context whose remoteAuthority is `seclab+*` is a tab's connection, so every
 * channel the client serves on it is checked. Channels on other connections
 * (shared process, Electron main) are untouched: those peers are trusted.
 */
setSeclabChannelGuard((ctx, channelName, method) => {
	const authority = (ctx as { remoteAuthority?: string } | undefined)?.remoteAuthority;
	if (typeof authority !== 'string' || !SECLAB_AUTHORITY.test(authority)) {
		return undefined;
	}
	const tabId = seclabResolveTabId(authority) ?? 'unregistered';
	const filter = new SeclabFilter(tabId, authority);
	return filter.checkChannel(channelName, method);
});
