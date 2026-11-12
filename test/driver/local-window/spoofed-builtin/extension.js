// Headless driver fixture: shows that it activated, as its own status bar item, and does nothing else.
const vscode = require('vscode');
exports.activate = context => {
	const item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left);
	item.text = 'seclab-local-window: spoofed-builtin active';
	item.show();
	context.subscriptions.push(item);
};
exports.deactivate = () => { };
