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
import { type Classifier, verifyWithheld, WITHHELD_MARKER, withheldReport } from '../tabd-src/obs/withheld.ts';

export const SETTINGS_WITHHELD_COMMAND = 'seclab.tabs.settingsWithheld';

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
	const reported = new Set<string>();
	// 0036 in this build? Without it nothing was withheld, so every call would be forged.
	// Checked once, on the first call (the bundle is large).
	let shipped: Promise<boolean> | undefined;
	let refusedLogged = 0;
	context.subscriptions.push(vscode.commands.registerCommand(SETTINGS_WITHHELD_COMMAND, async (arg: unknown): Promise<void> => {
		shipped ??= fileContains(path.join(vscode.env.appRoot, 'out', 'vs', 'workbench', 'workbench.desktop.main.js'), WITHHELD_MARKER);
		if (!classify || !(await shipped)) {
			log.warn(`${SETTINGS_WITHHELD_COMMAND} ignored: ${classify ? 'this build does not withhold settings (0036 marker missing)' : 'no settings classifier in this build'}`);
			return;
		}
		const r = verifyWithheld(arg, {
			authority: vscode.env.remoteAuthority,
			hostValue: key => (vscode.workspace.getConfiguration().inspect(key) as { globalLocalValue?: unknown } | undefined)?.globalLocalValue,
			classify,
		});
		if (r.refused && refusedLogged < 20) {
			refusedLogged++;
			log.warn(`${SETTINGS_WITHHELD_COMMAND}: ${r.refused} claim(s) refused (not in your user settings, or not what 0036 withholds)`);
		}
		if (r.ignored || !r.tabId) {
			log.warn(`${SETTINGS_WITHHELD_COMMAND} ignored: ${r.ignored ?? 'no tab'}`);
			return;
		}
		const fresh = r.accepted.filter(c => !reported.has(c.key));
		if (!fresh.length) {
			return;
		}
		try {
			const res = await (await getClient()).request<{ accepted: number; rejected: number }>('tab.events.report', { tabId: r.tabId, events: fresh.map(withheldReport) });
			// Only keys tabd took are done; if any were dropped (rate limit), a later call retries them all.
			if (res.rejected === 0) {
				for (const c of fresh) {
					reported.add(c.key);
				}
			}
		} catch (e) {
			log.warn(`could not report withheld settings: ${(e as Error).message}`);
		}
	}));
}
