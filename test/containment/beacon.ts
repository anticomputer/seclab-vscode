// Egress beacon: a host-side HTTP listener that records every request it gets.
//
// Several probes only prove anything if traffic actually reaches the host
// network: openExternal, asExternalUri, webview fetches, and _remoteCLI.openExternal.
// A return value does not prove egress -- the call can succeed while the request
// is blocked, and it can fail while the request still went out. A beacon hit is
// the evidence.
//
// Binds 127.0.0.1 only. It is a test oracle, not a service.
//
// A probe that runs INSIDE a tab cannot read this beacon's silence as evidence:
// from inside the sbx, `127.0.0.1` is the GUEST's loopback, so "no hit" is
// ambiguous between "contained" and "that address never meant this host". Such a
// probe runs a second listener on the same port INSIDE the tab and requires
// exactly one of the two to have been hit, which turns both outcomes into
// positive evidence. See test/agentic/browser/run.ts.
//
//   node test/containment/beacon.ts start <logfile> [port]
//   node test/containment/beacon.ts hits  <logfile>

import * as fs from 'node:fs';
import * as http from 'node:http';

const [mode, logfile, portArg] = process.argv.slice(2);
if (!mode || !logfile) {
	console.error('usage: beacon.ts start <logfile> [port] | hits <logfile>');
	process.exit(2);
}

export interface Hit {
	at: string;
	method: string;
	url: string;
	ua: string;
	origin: string;
	referer: string;
}

if (mode === 'hits') {
	const hits = readHits(logfile);
	console.log(JSON.stringify(hits, null, 2));
	process.exit(0);
}

export function readHits(file: string): Hit[] {
	if (!fs.existsSync(file)) {
		return [];
	}
	return fs.readFileSync(file, 'utf8').split('\n')
		.filter(l => l.trim())
		.map(l => JSON.parse(l) as Hit);
}

if (mode === 'start') {
	const port = Number(portArg ?? 18099);
	fs.writeFileSync(logfile, '');
	const server = http.createServer((req, res) => {
		const hit: Hit = {
			at: new Date().toISOString(),
			method: req.method ?? '',
			url: req.url ?? '',
			ua: String(req.headers['user-agent'] ?? ''),
			origin: String(req.headers.origin ?? ''),
			referer: String(req.headers.referer ?? ''),
		};
		fs.appendFileSync(logfile, `${JSON.stringify(hit)}\n`);
		// Permissive CORS so a webview fetch is not blocked before it leaves:
		// we are measuring egress, not testing the browser's policy.
		res.writeHead(200, {
			'content-type': 'text/plain',
			'access-control-allow-origin': '*',
		});
		res.end('beacon\n');
	});
	server.listen(port, '127.0.0.1', () => {
		console.log(`beacon on http://127.0.0.1:${port} -> ${logfile}`);
	});
	const stop = () => { server.close(); process.exit(0); };
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);
}
