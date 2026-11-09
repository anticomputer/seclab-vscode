/*---------------------------------------------------------------------------------------------
 *  `seclab.tabs.settingsWithheld` (EDR settings-withheld-notice): patch 0036 says which
 *  credential-looking settings it kept out of this window's tab. Anyone can call a command, so
 *  the payload is only a hint: tabd-src/obs/withheld.ts checks every claim against the host's
 *  own settings and 0036's classifier, and the tab is this window's own. Verified claims go to
 *  tabd as trusted `config.withheld` events; the notification comes back through the event
 *  stream like every other alert. The command returns nothing, so a caller learns nothing.
 *--------------------------------------------------------------------------------------------*/

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as vscode from 'vscode';
import type { TabdClient } from '../tabd-src/client.ts';
import { type Classifier, SETTINGS_WITHHELD_COMMAND, WITHHELD_MARKER, WithheldReceiver } from '../tabd-src/obs/withheld.ts';

/** Streams a (large) file looking for an ASCII literal. */
async function fileContains(file: string, needle: string): Promise<boolean> {
	let tail = '';
	try {
		for await (const chunk of fs.createReadStream(file, { encoding: 'latin1', highWaterMark: 1 << 20 })) {
			const s = tail + (chunk as string);
			if (s.includes(needle)) {
				return true;
			}
			tail = s.slice(-needle.length);
		}
	} catch {
		return false;
	}
	return false;
}

export function registerSettingsWithheld(context: vscode.ExtensionContext, getClient: () => Promise<TabdClient>, classify: Classifier | undefined, log: vscode.LogOutputChannel): void {
	const receiver = new WithheldReceiver({
		classify,
		// 0036 in this build? Without it nothing was withheld, so every call would be forged.
		shipped: () => fileContains(path.join(vscode.env.appRoot, 'out', 'vs', 'workbench', 'workbench.desktop.main.js'), WITHHELD_MARKER),
		authority: () => vscode.env.remoteAuthority,
		hostValue: key => (vscode.workspace.getConfiguration().inspect(key) as { globalLocalValue?: unknown } | undefined)?.globalLocalValue,
		report: async (tabId, events) => (await getClient()).request<{ accepted: number; rejected: number }>('tab.events.report', { tabId, events }),
		warn: m => log.warn(m),
	});
	context.subscriptions.push(vscode.commands.registerCommand(SETTINGS_WITHHELD_COMMAND, async (arg: unknown): Promise<void> => {
		await receiver.handle(arg);
	}));
}
