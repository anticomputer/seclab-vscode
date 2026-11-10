// A beacon that runs INSIDE a tab, on the same loopback port as the host beacon.
//
// Why both. The probe URL is `http://127.0.0.1:<port>/…`, and `127.0.0.1` means a different
// machine depending on who resolves it: the HOST's loopback for a page fetched on the host
// network, the GUEST's loopback for a page fetched inside the tab. With only the host beacon,
// a contained build produced silence, and silence is also what a broken probe, a dead
// listener or a page that never loaded produces. Absence is not containment.
//
// With a listener on both sides, every outcome is positive evidence and the verdict can
// require EXACTLY ONE of them to have been hit:
//
//   host beacon hit, tab listener quiet  -> the page was fetched on the HOST network
//   tab listener hit, host beacon quiet  -> the page was fetched INSIDE the tab
//   both, or neither                     -> inconclusive, and the run says so
//
// It writes its log into the run's workspace, which the sandbox mounts at the same absolute
// path it has on the host, so the harness reads it directly without a second exec.
//
//   node tab-beacon.mjs <logfile> <port> <nonce>
//
// The nonce is this run's, and only requests carrying it are recorded, so a stray request
// from anything else on that port cannot be counted as the probe.

import * as fs from 'node:fs';
import * as http from 'node:http';

const [logfile, portArg, nonce] = process.argv.slice(2);
if (!logfile || !portArg || !nonce) {
	console.error('usage: tab-beacon.mjs <logfile> <port> <nonce>');
	process.exit(2);
}
if (!/^[0-9a-f]{8,64}$/.test(nonce)) {
	console.error('tab-beacon: the nonce must be hex');
	process.exit(2);
}

fs.writeFileSync(logfile, '');
const server = http.createServer((req, res) => {
	const url = req.url ?? '';
	if (url.includes(nonce)) {
		fs.appendFileSync(logfile, `${JSON.stringify({
			at: new Date().toISOString(),
			side: 'tab',
			method: req.method ?? '',
			url,
			ua: String(req.headers['user-agent'] ?? ''),
		})}\n`);
	}
	res.writeHead(200, { 'content-type': 'text/plain', 'access-control-allow-origin': '*' });
	res.end('tab-beacon\n');
});
server.listen(Number(portArg), '127.0.0.1', () => {
	console.log(`tab-beacon on http://127.0.0.1:${portArg} -> ${logfile}`);
});
const stop = () => { server.close(); process.exit(0); };
process.on('SIGTERM', stop);
process.on('SIGINT', stop);
