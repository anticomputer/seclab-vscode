// Verdicts for the agents-in-the-tab spike: compares results-baseline.json with
// results-gated.json. A probe passes only if it was VULNERABLE on the unmodified client
// with its trigger sent, and CONTAINED on the gated run with its own gate decision
// recorded. Anything else is FAIL, or INVALID when the probe could not fail on baseline.
import * as fs from 'node:fs';
import * as path from 'node:path';

const RUN_DIR = process.env.RUN_DIR;
const read = mode => JSON.parse(fs.readFileSync(path.join(RUN_DIR, `results-${mode}.json`), 'utf8'));
const baseline = read('baseline');
const gated = read('gated');

const requiredDecision = {
	'A1': d => d.what === 'authenticate' && d.verdict === 'rewrite',
	'A16-write': d => d.what === 'resourceWrite' && d.verdict === 'deny',
	'A16-read': d => d.what === 'resourceRead' && d.verdict === 'deny',
	'A19-config': d => d.what === 'root/configChanged' && d.verdict === 'strip' && d.detail.split(',').includes('http.proxy'),
	'A18': d => d.what === 'client-tool' && d.verdict === 'deny',
};

const verdicts = baseline.results.map(b => {
	const g = gated.results.find(r => r.id === b.id);
	const decided = !!g && gated.gateDecisions.some(requiredDecision[b.id] ?? (() => false));
	let verdict;
	if (!baseline.armed || !gated.armed || !b.triggerSent || b.outcome !== 'vulnerable') {
		verdict = 'invalid'; // a disarmed run, or a probe that could not fail on baseline, proves nothing
	} else if (g && g.triggerSent && g.outcome === 'contained' && decided) {
		verdict = 'pass';
	} else {
		verdict = 'fail';
	}
	return { id: b.id, title: b.title, baseline: b.outcome, gated: g?.outcome ?? 'missing', gateDecision: decided, verdict };
});

fs.writeFileSync(path.join(RUN_DIR, 'verdicts.json'), JSON.stringify({ nonce: baseline.nonce, armed: baseline.armed, verdicts }, null, 1));
for (const v of verdicts) {
	console.log(`${v.id.padEnd(10)} baseline=${v.baseline.padEnd(10)} gated=${v.gated.padEnd(10)} => ${v.verdict.toUpperCase()}  ${v.title}`);
}
process.exit(verdicts.every(v => v.verdict === 'pass') ? 0 : 1);
