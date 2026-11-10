// Egress beacon: a host-side HTTP listener that records every request it gets.
//
// Several probes only prove anything if traffic actually reaches the host
// network: openExternal, asExternalUri, webview fetches, and _remoteCLI.openExternal.
// A return value does not prove egress -- the call can succeed while the request
// is blocked, and it can fail while the request still went out. A beacon hit is
// the evidence.
//
// Binds 127.0.0.1 by default. It is a test oracle, not a service.
//
// A probe that runs INSIDE a tab cannot use a loopback beacon as evidence: from
// inside the sbx, `127.0.0.1` is the guest's own loopback, so "no hit" is
// ambiguous between "contained" and "the address never meant the host". Such a
// probe passes an explicit bind address, which must be a PRIVATE (RFC 1918)
// address of this host, so that it is reachable from the host side and denied by
// a tab's fence, which allows the broker port alone. The guard below refuses
// anything else, so a run can never point the oracle at a routable address.
//
//   node test/containment/beacon.ts start <logfile> [port] [bind]
//   node test/containment/beacon.ts hits  <logfile>

import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';

const [mode, logfile, portArg, bindArg] = process.argv.slice(2);
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
	// Loopback, or a PRIVATE address this host actually holds. Anything else is
	// refused: a test oracle must never be reachable from outside this machine,
	// and a typo must not quietly publish one on a routable address.
	const bind = bindArg ?? '127.0.0.1';
	if (bind !== '127.0.0.1') {
		const isPrivate = /^10\./.test(bind) || /^192\.168\./.test(bind) || /^172\.(1[6-9]|2[0-9]|3[01])\./.test(bind);
		const held = Object.values(os.networkInterfaces()).flat()
			.some(i => i && i.family === 'IPv4' && i.address === bind);
		if (!isPrivate || !held) {
			console.error(`beacon: refusing to bind ${bind}: not a private address held by this host`);
			process.exit(2);
		}
	}
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
	server.listen(port, bind, () => {
		console.log(`beacon on http://${bind}:${port} -> ${logfile}`);
	});
	const stop = () => { server.close(); process.exit(0); };
	process.on('SIGTERM', stop);
	process.on('SIGINT', stop);
}
