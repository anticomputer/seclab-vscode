// Write-back gate 2b: the sync tick against a fake in-VM feed (no VM needed).
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { test } from 'node:test';
import { fileIdentity } from '../src/state.ts';
import { WriteBackEngine } from '../src/writeback.ts';
import { syncTick, type UpperReader } from '../src/writeback-feed.ts';

const SCRATCH = path.resolve(import.meta.dirname, '../../.work/test-scratch/writeback-feed');
const sha = (b: Buffer | string) => createHash('sha256').update(b).digest('hex');

/** A fake upper layer: path -> entry; answers list/get/mirror like seclab-wb-feed. */
class FakeUpper implements UpperReader {
	files = new Map<string, { content: Buffer; mode: number }>();
	wh = new Set<string>();
	opq = new Set<string>();
	err = false;
	extraGet?: string;
	async feed(mode: 'list' | 'get' | 'mirror', input = ''): Promise<string> {
		const out: string[] = [];
		if (mode === 'list') {
			for (const [p, f] of this.files) {
				out.push(JSON.stringify({ p, k: 'file', m: f.mode, n: 1, s: f.content.length, h: f.content.length > 64 ? undefined : sha(f.content) }));
			}
			this.wh.forEach(p => out.push(JSON.stringify({ p, k: 'wh' })));
			this.opq.forEach(p => out.push(JSON.stringify({ p, k: 'opq' })));
			if (this.err) {
				out.push(JSON.stringify({ p: 'unreadable', k: 'err' }));
			}
			out.push(JSON.stringify({ done: true, count: out.length, truncated: false }));
		} else {
			for (const l of input.split('\n').filter(Boolean)) {
				const r = JSON.parse(l) as { p: string; expect?: string; b64?: string };
				const f = this.files.get(r.p);
				if (mode === 'get') {
					out.push(JSON.stringify(f ? { p: r.p, b64: f.content.toString('base64'), h: sha(f.content), m: f.mode, n: 1 } : { p: r.p, err: 'gone' }));
				} else if (f && sha(f.content) === r.expect) {
					f.content = Buffer.from(r.b64 ?? '', 'base64');
					out.push(JSON.stringify({ p: r.p, ok: true, h: sha(f.content) }));
				} else {
					out.push(JSON.stringify({ p: r.p, err: 'changed by the tab' }));
				}
			}
			if (this.extraGet) {
				out.push(JSON.stringify({ p: this.extraGet, b64: '' }));
			}
		}
		return out.join('\n') + '\n';
	}
}

function setup(name: string) {
	const dir = path.join(SCRATCH, name);
	fs.rmSync(dir, { recursive: true, force: true });
	const root = path.join(dir, 'ws');
	fs.mkdirSync(path.join(root, 'd', 'sub'), { recursive: true });
	fs.writeFileSync(path.join(root, 'a.txt'), 'host a\n');
	fs.writeFileSync(path.join(root, 'd', 'b.txt'), 'host b\n');
	fs.writeFileSync(path.join(root, 'd', 'sub', 'c.txt'), 'host c\n');
	const e = new WriteBackEngine({ root, rootIdentity: fileIdentity(root), statePath: path.join(dir, 'wb.json'), ignoredBy: () => new Set() });
	return { root, e, up: new FakeUpper() };
}
const read = (root: string, p: string) => fs.readFileSync(path.join(root, p), 'utf8');

test('feed: a tab edit is applied once; an unchanged upper entry is not re-applied', async () => {
	const { root, e, up } = setup('apply');
	up.files.set('a.txt', { content: Buffer.from('tab a\n'), mode: 0o644 });
	up.files.set('new/n.txt', { content: Buffer.from('new\n'), mode: 0o644 });
	const r1 = await syncTick(e, up, root, 64);
	assert.deepEqual(r1.applied.sort(), ['a.txt', 'new/n.txt']);
	assert.equal(read(root, 'a.txt'), 'tab a\n');
	const r2 = await syncTick(e, up, root, 64);
	assert.deepEqual(r2.applied, [], 'synced entries are skipped');
	up.files.set('a.txt', { content: Buffer.from('tab a 2\n'), mode: 0o644 });
	assert.deepEqual((await syncTick(e, up, root, 64)).applied, ['a.txt']);
});

test('feed: host edits to a synced file are mirrored into the upper copy (CAS)', async () => {
	const { root, e, up } = setup('mirror');
	up.files.set('a.txt', { content: Buffer.from('tab a\n'), mode: 0o644 });
	await syncTick(e, up, root, 64);
	fs.writeFileSync(path.join(root, 'a.txt'), 'host edit\n');
	const r = await syncTick(e, up, root, 64);
	assert.deepEqual(r.mirrored, ['a.txt']);
	assert.equal(up.files.get('a.txt')?.content.toString(), 'host edit\n');
	const r2 = await syncTick(e, up, root, 64);
	assert.deepEqual([r2.applied, r2.mirrored, r2.held], [[], [], []], 'after the mirror both sides agree');
	// The tab edits again: an ordinary change, applied (not a conflict).
	up.files.set('a.txt', { content: Buffer.from('tab again\n'), mode: 0o644 });
	assert.deepEqual((await syncTick(e, up, root, 64)).applied, ['a.txt']);
	assert.equal(read(root, 'a.txt'), 'tab again\n');
});

test('feed: whiteouts are deletions; an opaque directory is one held directory deletion (MM-1); held entries the tab removes are forgotten', async () => {
	const { root, e, up } = setup('delete');
	up.wh.add('a.txt');
	up.opq.add('d');
	up.files.set('d/kept.txt', { content: Buffer.from('k\n'), mode: 0o644 });
	const r = await syncTick(e, up, root, 64);
	assert.ok(!fs.existsSync(path.join(root, 'a.txt')));
	assert.ok(fs.existsSync(path.join(root, 'd', 'b.txt')) && fs.existsSync(path.join(root, 'd', 'sub', 'c.txt')), 'replaced directory: host files kept');
	assert.ok(r.held.some(h => h.path === 'd' && h.reasons.includes('directory deletion')), JSON.stringify(r.held));
	assert.equal(read(root, 'd/kept.txt'), 'k\n');
	// MM-2: an incomplete listing applies no deletions.
	const { root: ir, e: ie, up: iu } = setup('incomplete');
	iu.wh.add('a.txt');
	iu.err = true;
	await syncTick(ie, iu, ir, 64);
	assert.ok(fs.existsSync(path.join(ir, 'a.txt')), 'no deletion from an incomplete listing');
	const { root: r2root, e: e2, up: up2 } = setup('forget');
	up2.files.set('.envrc', { content: Buffer.from('x\n'), mode: 0o644 });
	assert.equal((await syncTick(e2, up2, r2root, 64)).held.length, 1);
	up2.files.delete('.envrc');
	await syncTick(e2, up2, r2root, 64);
	assert.equal(e2.pending().length, 0, 'a held entry the tab removed is no longer pending');
});

test('feed: over-cap files are refused, never written; a feed answering unasked paths is rejected', async () => {
	const { root, e, up } = setup('caps');
	up.files.set('big.bin', { content: Buffer.alloc(100, 1), mode: 0o644 });
	const r = await syncTick(e, up, root, 64);
	assert.match(r.refused.map(x => x.reason).join(), /per-file cap/);
	assert.ok(!fs.existsSync(path.join(root, 'big.bin')));
	up.files.set('x.txt', { content: Buffer.from('x'), mode: 0o644 });
	up.extraGet = '.git/hooks/pre-commit';
	await assert.rejects(syncTick(e, up, root, 64), /not asked/);
	assert.ok(!fs.existsSync(path.join(root, '.git')));
});

test('feed: a tab cannot create a git repository in a host folder that has none', async () => {
	const { root, e, up } = setup('no-repo');
	up.files.set('.git/HEAD', { content: Buffer.from('ref: refs/heads/main\n'), mode: 0o644 });
	up.files.set(`.git/objects/ab/${'c'.repeat(38)}`, { content: Buffer.from('x'), mode: 0o444 });
	const r = await syncTick(e, up, root, 64);
	assert.equal(r.applied.length, 0, JSON.stringify(r.applied));
	assert.ok(!fs.existsSync(path.join(root, '.git')));
	assert.equal(r.held.length, 2);
});

test('feed: tab-local files are never mirrored from the host (MM-3)', async () => {
	const { root, e, up } = setup('tablocal');
	fs.mkdirSync(path.join(root, 'node_modules', 'x'), { recursive: true });
	fs.writeFileSync(path.join(root, 'node_modules', 'x', 'i.js'), 'host copy\n');
	up.files.set('node_modules/x/i.js', { content: Buffer.from('tab copy\n'), mode: 0o644 });
	const r1 = await syncTick(e, up, root, 64);
	assert.match(r1.refused.map(x => x.reason).join(), /tab-local/);
	const r2 = await syncTick(e, up, root, 64);
	assert.deepEqual(r2.mirrored, []);
	assert.equal(up.files.get('node_modules/x/i.js')?.content.toString(), 'tab copy\n');
});

test('decide: approve is bound to the shown signature; reject restores the host version in the tab; always is refused for agent config', async () => {
	const { WriteBackManager } = await import('../src/writeback-manager.ts');
	const dir = path.join(SCRATCH, 'decide');
	fs.rmSync(dir, { recursive: true, force: true });
	const root = path.join(dir, 'ws');
	fs.mkdirSync(path.join(root, '.git'), { recursive: true });
	fs.writeFileSync(path.join(root, 'Makefile'), 'all:\n\techo host\n');
	const tabId = 't-' + 'a'.repeat(26);
	const pendingSeen: number[] = [];
	const m = new WriteBackManager({ dir: path.join(dir, 'state'), intervalMs: 3_600_000, onPending: (_t, n) => pendingSeen.push(n) });
	const up = new FakeUpper();
	m.start(tabId, root, fileIdentity(root), up);
	try {
		up.files.set('Makefile', { content: Buffer.from('all:\n\techo tab\n'), mode: 0o644 });
		up.files.set('.envrc', { content: Buffer.from('export X=1\n'), mode: 0o644 });
		up.files.set('AGENTS.md', { content: Buffer.from('be nice\n'), mode: 0o644 });
		await m.sync(tabId);
		const pend = m.status(tabId).pending;
		assert.deepEqual(pend.map(p => p.path).sort(), ['.envrc', 'AGENTS.md', 'Makefile']);
		assert.equal(pendingSeen.at(-1), 3);
		const mk = pend.find(p => p.path === 'Makefile')!;
		const c = await m.content(tabId, 'Makefile') as { host: { b64: string }; tab: { b64: string } };
		assert.equal(Buffer.from(c.host.b64, 'base64').toString(), 'all:\n\techo host\n');
		assert.equal(Buffer.from(c.tab.b64, 'base64').toString(), 'all:\n\techo tab\n');
		await assert.rejects(m.decide(tabId, 'Makefile', 'approve', 'f'.repeat(64)), /changed this entry since it was shown/);
		// The tab changes the file after it was shown: approval must refuse.
		up.files.set('Makefile', { content: Buffer.from('all:\n\tcurl x\n'), mode: 0o644 });
		await assert.rejects(m.decide(tabId, 'Makefile', 'approve', mk.sig), /changed/);
		assert.equal(fs.readFileSync(path.join(root, 'Makefile'), 'utf8'), 'all:\n\techo host\n');
		// Reject restores the host's version into the tab.
		await m.sync(tabId);
		const mk2 = m.status(tabId).pending.find(p => p.path === 'Makefile')!;
		assert.match((await m.decide(tabId, 'Makefile', 'reject', mk2.sig)).result, /restored in the tab/);
		assert.equal(up.files.get('Makefile')?.content.toString(), 'all:\n\techo host\n');
		await m.sync(tabId);
		assert.ok(!m.status(tabId).pending.some(p => p.path === 'Makefile'), 'not re-prompted');
		// Approve applies exactly what was shown.
		const env = m.status(tabId).pending.find(p => p.path === '.envrc')!;
		assert.equal((await m.decide(tabId, '.envrc', 'approve', env.sig)).result, 'applied');
		assert.equal(fs.readFileSync(path.join(root, '.envrc'), 'utf8'), 'export X=1\n');
		// "Always" is never available for agent configuration.
		const ag = m.status(tabId).pending.find(p => p.path === 'AGENTS.md')!;
		await assert.rejects(m.decide(tabId, 'AGENTS.md', 'always', ag.sig), /not available/);
		assert.ok(!fs.existsSync(path.join(root, 'AGENTS.md')));
	} finally {
		m.stop(tabId);
	}
});

test('decide: the diff shows exactly the held bytes; a tab showing other content to the reviewer is refused (OO-1)', async () => {
	const { WriteBackManager } = await import('../src/writeback-manager.ts');
	const dir = path.join(SCRATCH, 'oo1');
	fs.rmSync(dir, { recursive: true, force: true });
	const root = path.join(dir, 'ws');
	fs.mkdirSync(root, { recursive: true });
	const tabId = 't-' + 'b'.repeat(26);
	const m = new WriteBackManager({ dir: path.join(dir, 'state'), intervalMs: 3_600_000 });
	const up = new FakeUpper();
	m.start(tabId, root, fileIdentity(root), up);
	try {
		const evil = { content: Buffer.from('{"tasks":[{"command":"evil"}]}'), mode: 0o644 };
		up.files.set('.vscode/tasks.json', evil);
		await m.sync(tabId);
		const p = m.status(tabId).pending[0];
		// The tab swaps in a harmless version only while the reviewer reads it.
		up.files.set('.vscode/tasks.json', { content: Buffer.from('{"tasks":[]}'), mode: 0o644 });
		await assert.rejects(m.content(tabId, '.vscode/tasks.json'), /changed this entry since it was held/);
		up.files.set('.vscode/tasks.json', evil);
		const shown = await m.content(tabId, '.vscode/tasks.json') as { sig: string; tab: { b64: string } };
		assert.equal(Buffer.from(shown.tab.b64, 'base64').toString(), '{"tasks":[{"command":"evil"}]}', 'what is shown is what is held');
		assert.equal(shown.sig, p.sig);
		assert.throws(() => m.confirmDeletes(tabId, 5), /changed since they were shown/, 'confirmation bound to the count shown (OO-6)');
	} finally {
		m.stop(tabId);
	}
});
