/*---------------------------------------------------------------------------------------------
 *  seclab-vscode: named argument validators for the RPC capability filter.
 *
 *  A policy entry names its validator (`"validator": "<name>"` in policy.json); the filter
 *  looks the name up here and denies the call if the name is unknown, the validator throws,
 *  or it returns a reason. Every validator accepts only shapes it recognises: anything else
 *  is a reason to deny.
 *
 *  This module has no imports on purpose. Whatever needs the workbench (URI revival, the
 *  command registry, the window's context keys) is injected through the context, so the
 *  tests in test/containment/arg-validators.test.ts import THIS file, not a model of it.
 *--------------------------------------------------------------------------------------------*/

export interface SeclabValidatorContext {
	/** `seclab+<tabId>`, from the connection. */
	readonly authority: string;
	/** Revive as the consumer will; a reason when it is not a canonical resource of this tab. */
	checkTabUri(raw: unknown): string | undefined;
	/** A handler is registered for this id right now (by anyone). */
	isCommandRegistered(id: string): boolean;
	/** A command id the trusted side owns (generated from the inventory and the policy). */
	isTrustedCommandId(id: string): boolean;
	readonly commandDenyPrefixes: readonly string[];
	/** A context key the workbench declares (`RawContextKey.all()`). */
	isCoreContextKey(key: string): boolean;
	/** The key's current value in the window's global context. */
	contextKeyValue(key: string): unknown;
	/**
	 * The value as `_setContext` will store it (URIs stringified, as `stringifyURIs` does),
	 * serialized: comparable with a later `contextKeyValue`, which is a clone.
	 */
	contextValueFingerprint(value: unknown): string | undefined;
	/** Fingerprint of what this tab last stored, per key: a key someone else has since written is not the tab's. */
	readonly tabContextKeys: Map<string, string | undefined>;
}

/** @returns a reason to deny, or undefined to let the call through. */
export type SeclabValidator = (args: readonly unknown[], ctx: SeclabValidatorContext) => string | undefined;

const EXTENSION_ID = /^[A-Za-z0-9][A-Za-z0-9-]*\.[A-Za-z0-9][A-Za-z0-9._-]*$/;
const COMMAND_ID = /^[^\s\u0000-\u001f]{1,256}$/;
const CONTEXT_KEY = /^[A-Za-z0-9_$][A-Za-z0-9_.:$/@-]{0,255}$/;
const CONTEXT_KEY_DENY_PREFIXES = ['seclab.', 'seclab:', 'config.'];
const MAX_ID = 256;
const MAX_SECRET_KEY = 1024;
const MAX_SECRET_VALUE = 64 * 1024;
const MAX_CONTEXT_STRING = 4096;
const MAX_CONTEXT_ITEMS = 1000;

function isPlainObject(v: unknown): v is Record<string, unknown> {
	if (typeof v !== 'object' || v === null || Array.isArray(v)) {
		return false;
	}
	const proto = Object.getPrototypeOf(v);
	return proto === Object.prototype || proto === null;
}

function extensionId(v: unknown, what: string): string | undefined {
	if (typeof v !== 'string' || v.length > MAX_ID || !EXTENSION_ID.test(v)) {
		return `${what} is not an extension id`;
	}
	return undefined;
}

function arity(args: readonly unknown[], min: number, max: number): string | undefined {
	return args.length < min || args.length > max ? `expected ${min}-${max} arguments, got ${args.length}` : undefined;
}

/**
 * `$onExtensionActivationError(extensionId, error, missingExtensionDependency)`.
 * A truthy third argument reaches `_handleMissingNotInstalledDependency`, which prompts the
 * user to INSTALL an extension the tab named. Only `null`/`undefined` is accepted there.
 */
const activationErrorNoInstallPrompt: SeclabValidator = (args) => {
	const bad = arity(args, 2, 3);
	if (bad) {
		return bad;
	}
	const id = args[0];
	if (!isPlainObject(id) || typeof id.value !== 'string' || id.value.length > MAX_ID) {
		return 'argument 0 is not an extension identifier';
	}
	if (!isPlainObject(args[1])) {
		return 'argument 1 is not a serialized error';
	}
	if (args[2] !== null && args[2] !== undefined) {
		return 'a missing-dependency report would prompt the user to install an extension the tab named';
	}
	return undefined;
};

/**
 * `$registerCommand(id)`. The registry is last-writer-wins (`CommandsRegistry` unshifts), so a
 * tab registering a trusted id would receive every invocation of it until the trusted side
 * registers again, including arguments trusted callers pass. Refused: the fork's own prefixes,
 * any id the trusted side owns (registered now or later), and any id already registered.
 */
const tabCommandRegistration: SeclabValidator = (args, ctx) => {
	const bad = arity(args, 1, 1);
	if (bad) {
		return bad;
	}
	const id = args[0];
	if (typeof id !== 'string' || !COMMAND_ID.test(id)) {
		return 'argument 0 is not a command id';
	}
	if (ctx.commandDenyPrefixes.some(p => id.startsWith(p))) {
		return 'command id is in a reserved namespace';
	}
	if (ctx.isTrustedCommandId(id)) {
		return 'command id belongs to the trusted side';
	}
	if (ctx.isCommandRegistered(id)) {
		return 'command id is already registered';
	}
	return undefined;
};

/**
 * `$initializeExtensionStorage(shared, extensionId)`. The id is used verbatim as a storage KEY
 * in the profile or workspace store, so without a shape check it names any key, not just
 * extension state. The partition (patch 0011) prefixes it with the tab; this keeps it an id.
 */
const extensionStorageInit: SeclabValidator = (args) => {
	return arity(args, 2, 2)
		?? (typeof args[0] !== 'boolean' ? 'argument 0 is not a boolean' : undefined)
		?? extensionId(args[1], 'argument 1');
};

/** `$setValue(shared, extensionId, value)`: the same key, and a state object. */
const extensionStorageSet: SeclabValidator = (args) => {
	return arity(args, 3, 3)
		?? (typeof args[0] !== 'boolean' ? 'argument 0 is not a boolean' : undefined)
		?? extensionId(args[1], 'argument 1')
		?? (!isPlainObject(args[2]) ? 'argument 2 is not a state object' : undefined);
};

function secretKey(v: unknown): string | undefined {
	return typeof v !== 'string' || v.length > MAX_SECRET_KEY ? 'argument 1 is not a secret key' : undefined;
}

/** `$getPassword` / `$deletePassword(extensionId, key)`. Partitioned per tab by patch 0011. */
const secretByKey: SeclabValidator = (args) => {
	return arity(args, 2, 2) ?? extensionId(args[0], 'argument 0') ?? secretKey(args[1]);
};

/** `$setPassword(extensionId, key, value)`. */
const secretSet: SeclabValidator = (args) => {
	return arity(args, 3, 3) ?? extensionId(args[0], 'argument 0') ?? secretKey(args[1])
		?? (typeof args[2] !== 'string' || args[2].length > MAX_SECRET_VALUE ? 'argument 2 is not a secret value' : undefined);
};

/** `$getKeys(extensionId)`. */
const secretKeys: SeclabValidator = (args) => {
	return arity(args, 1, 1) ?? extensionId(args[0], 'argument 0');
};

function isPosition(v: unknown): boolean {
	return isPlainObject(v) && Number.isInteger(v.lineNumber) && Number.isInteger(v.column)
		&& (v.lineNumber as number) >= 1 && (v.column as number) >= 1;
}

/**
 * Command arguments of `_executeHoverProvider` / `_executeCompletionItemProvider`: a model
 * URI and a position, then (completion only) a trigger character and a resolve count. The
 * handler calls `ITextModelService.createModelReference(uri)`, and in a remote window `file:`
 * is the HOST disk, so the URI must be this tab's own resource or the call reads host files
 * back through word-based completions and UI-side hover providers.
 */
const tabModelPosition: SeclabValidator = (args, ctx) => {
	const bad = arity(args, 2, 4);
	if (bad) {
		return bad;
	}
	const uri = args[0];
	if (!isPlainObject(uri) || uri.$mid !== 1) {
		return 'argument 0 is not a marshalled URI';
	}
	const reason = ctx.checkTabUri(uri);
	if (reason) {
		return reason;
	}
	if (!isPosition(args[1])) {
		return 'argument 1 is not a position';
	}
	if (args.length > 2 && args[2] !== undefined && args[2] !== null
		&& !(typeof args[2] === 'string' && args[2].length <= 16)) {
		return 'argument 2 is not a trigger character';
	}
	if (args.length > 3 && args[3] !== undefined && args[3] !== null
		&& !(Number.isInteger(args[3]) && (args[3] as number) >= 0 && (args[3] as number) <= 1000)) {
		return 'argument 3 is not an item count';
	}
	return undefined;
};

function contextPrimitive(v: unknown): boolean {
	return v === null || v === undefined || typeof v === 'boolean'
		|| (typeof v === 'number' && Number.isFinite(v))
		|| (typeof v === 'string' && v.length <= MAX_CONTEXT_STRING);
}

const URI_FIELDS = new Set(['$mid', 'scheme', 'authority', 'path', 'query', 'fragment', 'external', 'fsPath', '_sep']);

/** A marshalled URI, which `_setContext` stores as its string. Nothing else nested. */
function marshalledUri(v: unknown): boolean {
	return isPlainObject(v) && v.$mid === 1 && typeof v.scheme === 'string'
		&& Object.entries(v).every(([k, f]) => URI_FIELDS.has(k)
			&& (k === '$mid' || k === '_sep' ? typeof f === 'number' : typeof f === 'string' && f.length <= MAX_CONTEXT_STRING));
}

function contextItem(v: unknown): boolean {
	return contextPrimitive(v) || marshalledUri(v);
}

/**
 * Command arguments of `_setContext(key, value)`. The handler writes the window's GLOBAL
 * context, so a tab could flip core or Tab Manager when-clauses and surface trusted menus and
 * keybindings for host commands. Refused: declared core keys, reserved prefixes, keys someone
 * else has written, and values that are not small primitives or URIs (or flat lists/maps of
 * them).
 */
const setContextKey: SeclabValidator = (args, ctx) => {
	const bad = arity(args, 1, 2);
	if (bad) {
		return bad;
	}
	const key = args[0];
	if (typeof key !== 'string' || !CONTEXT_KEY.test(key)) {
		return 'argument 0 is not a context key';
	}
	if (CONTEXT_KEY_DENY_PREFIXES.some(p => key.startsWith(p))) {
		return 'context key is in a reserved namespace';
	}
	if (ctx.isCoreContextKey(key)) {
		return 'context key is declared by the workbench';
	}
	const value = args[1];
	if (Array.isArray(value)) {
		if (value.length > MAX_CONTEXT_ITEMS || !value.every(contextItem)) {
			return 'argument 1 is not a list of primitives';
		}
	} else if (isPlainObject(value) && !('$mid' in value)) {
		const entries = Object.entries(value);
		if (entries.length > MAX_CONTEXT_ITEMS || !entries.every(([k, v]) => k.length <= MAX_ID && contextItem(v))) {
			return 'argument 1 is not a map of primitives';
		}
	} else if (!contextItem(value)) {
		return 'argument 1 is not a primitive';
	}
	const current = ctx.contextKeyValue(key);
	if (current !== undefined) {
		const mine = ctx.tabContextKeys.has(key) && ctx.tabContextKeys.get(key) === ctx.contextValueFingerprint(current);
		if (!mine) {
			return 'context key has a value this tab did not set';
		}
	}
	ctx.tabContextKeys.set(key, ctx.contextValueFingerprint(value));
	return undefined;
};

export const SECLAB_VALIDATORS: ReadonlyMap<string, SeclabValidator> = new Map([
	['activationErrorNoInstallPrompt', activationErrorNoInstallPrompt],
	['tabCommandRegistration', tabCommandRegistration],
	['extensionStorageInit', extensionStorageInit],
	['extensionStorageSet', extensionStorageSet],
	['secretByKey', secretByKey],
	['secretSet', secretSet],
	['secretKeys', secretKeys],
	['tabModelPosition', tabModelPosition],
	['setContextKey', setContextKey],
]);

/** Run a named validator, failing closed on an unknown name or a throw. */
export function seclabValidate(name: string, args: readonly unknown[], ctx: SeclabValidatorContext): string | undefined {
	const v = SECLAB_VALIDATORS.get(name);
	if (!v) {
		return `validator ${name} is not implemented`;
	}
	try {
		return v(args, ctx);
	} catch (e) {
		return `validator ${name} failed: ${e instanceof Error ? e.message : String(e)}`;
	}
}
