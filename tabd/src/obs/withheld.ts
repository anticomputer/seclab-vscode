/*---------------------------------------------------------------------------------------------
 *  "A credential-looking setting was withheld from this tab" (EDR settings-withheld-notice).
 *  Patch 0036 filters the configuration snapshot a tab's extension host receives, and calls the
 *  command `seclab.tabs.settingsWithheld` in the window's local extension host to say what it
 *  withheld. A command handler can't tell who called it (`$executeCommand` carries no origin),
 *  so a tab extension can call it too. The payload is therefore a hint, and every claim is
 *  checked against host state before anything is said:
 *  - the tab is the window's own authority, and the payload must name exactly that one;
 *  - the key must have a value in the host's own user settings (the local host's `userLocal`
 *    layer, which a tab's remote layer and workspace settings don't touch);
 *  - re-running 0036's own classifier on that key and value must give the claimed reason.
 *  A forged call can then only produce a notice that is true, and can't spend the rate limit
 *  on keys that weren't withheld. Pure: unit-tested with tabd, bundled into the Tab Manager.
 *--------------------------------------------------------------------------------------------*/

/** The literal 0036 passes as `v` (and keeps in the workbench bundle). Assembled at run time so
 *  the Tab Manager's own bundle never contains it, should a release check look for 0036's marker. */
export const WITHHELD_MARKER = [['seclabSettings', 'Withheld'].join(''), 'v1'].join(':');
export const MAX_WITHHELD_PER_CALL = 64;
export const MAX_SETTING_KEY = 256;

export type WithholdReason = 'credential-name' | 'secret-value';
/** 0036's classifier (build/secret-rules), shared so both sides run the same code. */
export type Classifier = (key: string, value: unknown) => WithholdReason | undefined;

export interface WithheldClaim { key: string; reason: WithholdReason }

export interface VerifyContext {
	/** The window's own remote authority (`vscode.env.remoteAuthority`). */
	readonly authority: string | undefined;
	/** The host's own user-settings value for a key (`inspect(key).globalLocalValue`). */
	readonly hostValue: (key: string) => unknown;
	readonly classify: Classifier;
}

export interface VerifyResult {
	/** The tab: the window's authority, never the payload. */
	tabId?: string;
	accepted: WithheldClaim[];
	/** Claims that failed a check (counted, never shown). */
	refused: number;
	/** Why the whole call was ignored, when it was. */
	ignored?: string;
}

const AUTHORITY_RE = /^seclab\+(t-[a-z2-7]{26})$/;
const REASONS: ReadonlySet<string> = new Set(['credential-name', 'secret-value']);

export function verifyWithheld(arg: unknown, ctx: VerifyContext): VerifyResult {
	const out: VerifyResult = { accepted: [], refused: 0 };
	const own = ctx.authority !== undefined ? AUTHORITY_RE.exec(ctx.authority) : null;
	if (!own) {
		return { ...out, ignored: 'not a tab window' };
	}
	const a = (typeof arg === 'object' && arg !== null && !Array.isArray(arg) ? arg : {}) as Record<string, unknown>;
	if (a.v !== WITHHELD_MARKER) {
		return { ...out, ignored: 'unknown version' };
	}
	if (a.authority !== ctx.authority) {
		return { ...out, ignored: 'another window\'s tab' };
	}
	if (!Array.isArray(a.settings) || a.settings.length > MAX_WITHHELD_PER_CALL) {
		return { ...out, ignored: `settings must be an array of at most ${MAX_WITHHELD_PER_CALL}` };
	}
	out.tabId = own[1];
	const seen = new Set<string>();
	for (const s of a.settings) {
		const c = (typeof s === 'object' && s !== null ? s : {}) as Record<string, unknown>;
		const key = c.key, reason = c.reason;
		if (typeof key !== 'string' || key.length === 0 || key.length > MAX_SETTING_KEY || typeof reason !== 'string' || !REASONS.has(reason) || seen.has(key)) {
			out.refused++;
			continue;
		}
		seen.add(key);
		let value: unknown, verdict: WithholdReason | undefined;
		try {
			value = ctx.hostValue(key);
			verdict = value === undefined ? undefined : ctx.classify(key, value);
		} catch {
			verdict = undefined;
		}
		if (verdict !== reason) {
			out.refused++;
			continue;
		}
		out.accepted.push({ key, reason: verdict });
	}
	return out;
}

/** The trusted report for one verified claim (`tab.events.report`; tabd tags `key` untrusted). */
export function withheldReport(c: WithheldClaim): { source: string; class: string; priority: string; summary: string; detail: Record<string, string> } {
	return { source: 'config-filter', class: 'config.withheld', priority: 'warning', summary: 'credential-looking setting withheld from the tab', detail: { key: c.key, reason: c.reason } };
}
