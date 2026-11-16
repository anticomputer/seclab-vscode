// A minimal `vscode` module for the Tab Manager's unit tests: records what the extension shows
// and registers, and answers each dialog from a queue the test fills. Only what the tested
// modules use is here; anything else is undefined, so a test can't pass by silently skipping UI.

type Answer = unknown | ((...args: unknown[]) => unknown);

export const calls: Array<{ fn: string; args: unknown[] }> = [];
export const answers: Record<string, Answer[]> = {};
export const commandsRegistered = new Map<string, (...args: unknown[]) => unknown>();
const selectionListeners: Array<(e: unknown) => void> = [];

export function reset(): void {
	calls.length = 0;
	for (const k of Object.keys(answers)) {
		delete answers[k];
	}
	commandsRegistered.clear();
	selectionListeners.length = 0;
	window.state.focused = true;
	window.state.active = true;
}

function answer(fn: string, args: unknown[]): unknown {
	calls.push({ fn, args });
	const a = answers[fn]?.shift();
	return typeof a === 'function' ? (a as (...x: unknown[]) => unknown)(...args) : a;
}

export function fireSelectionChange(e: unknown): void {
	for (const l of [...selectionListeners]) {
		l(e);
	}
}

export class Disposable {
	private readonly fn: () => void;
	constructor(fn: () => void) {
		this.fn = fn;
	}
	dispose(): void {
		this.fn();
	}
}

export const StatusBarAlignment = { Left: 1, Right: 2 } as const;
export const TextEditorSelectionChangeKind = { Keyboard: 1, Mouse: 2, Command: 3 } as const;

export class Uri {
	readonly scheme: string;
	readonly path: string;
	readonly query: string;
	private constructor(scheme: string, path: string, query: string) {
		this.scheme = scheme;
		this.path = path;
		this.query = query;
	}
	static from(c: { scheme: string; path?: string; query?: string }): Uri {
		return new Uri(c.scheme, c.path ?? '', c.query ?? '');
	}
	toString(): string {
		return `${this.scheme}:${this.path}${this.query ? `?${this.query}` : ''}`;
	}
}

export const window = {
	state: { focused: true, active: true },
	createStatusBarItem: (..._args: unknown[]) => ({ text: '', tooltip: '', command: undefined as unknown, show() { }, hide() { }, dispose() { } }),
	showInformationMessage: (...args: unknown[]) => Promise.resolve(answer('showInformationMessage', args)),
	showWarningMessage: (...args: unknown[]) => Promise.resolve(answer('showWarningMessage', args)),
	showErrorMessage: (...args: unknown[]) => Promise.resolve(answer('showErrorMessage', args)),
	showInputBox: (...args: unknown[]) => Promise.resolve(answer('showInputBox', args)),
	showQuickPick: (...args: unknown[]) => Promise.resolve(answer('showQuickPick', args)),
	onDidChangeTextEditorSelection: (l: (e: unknown) => void) => {
		selectionListeners.push(l);
		return new Disposable(() => selectionListeners.splice(selectionListeners.indexOf(l), 1));
	},
};

export const commands = {
	registerCommand: (id: string, fn: (...args: unknown[]) => unknown) => {
		commandsRegistered.set(id, fn);
		return new Disposable(() => commandsRegistered.delete(id));
	},
	executeCommand: (...args: unknown[]) => Promise.resolve(answer('executeCommand', args)),
};

export const workspace = {
	registerTextDocumentContentProvider: (..._args: unknown[]) => new Disposable(() => undefined),
};

/** A log channel that records nothing. */
export const log = { trace() { }, debug() { }, info() { }, warn() { }, error() { } };
