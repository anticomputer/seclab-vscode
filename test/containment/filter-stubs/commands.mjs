export const registered = new Set();
export const CommandsRegistry = { getCommand: id => (registered.has(id) ? { id } : undefined) };
