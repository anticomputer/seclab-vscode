export const registered = new Set();
export const handlers = new Map();
export const ICommandService = { toString: () => 'ICommandService' };
export const CommandsRegistry = {
	getCommand: id => (registered.has(id) ? { id } : undefined),
	registerCommand: (id, handler) => { handlers.set(id, handler); return { dispose() { handlers.delete(id); } }; },
};
