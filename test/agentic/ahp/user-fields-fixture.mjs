// Dry-run fixture for the /copilot_internal/user field-name measurement (user-fields.ts).
// Serves GET /copilot_internal/user with a canary VALUE in every field, at every depth, so the
// harness can prove that no value reaches the run directory, the broker's logs or its audit:
// only names may. Writes OUT/ca.pem and nothing else. Env: NONCE, OUT.
import { execFileSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as https from 'node:https';

const { NONCE, OUT } = process.env;
const tls = '/run/fixture-tls';
const ossl = (...a) => execFileSync('openssl', a, { cwd: tls, stdio: ['ignore', 'ignore', 'pipe'] });
ossl('req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '1', '-subj', `/CN=seclab user-fields fixture CA ${NONCE}`,
	'-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
ossl('req', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'leaf.key', '-out', 'leaf.csr', '-subj', '/CN=api.ghe.example.test');
fs.writeFileSync(`${tls}/leaf.ext`, 'subjectAltName=DNS:api.ghe.example.test\nextendedKeyUsage=serverAuth\n');
ossl('x509', '-req', '-in', 'leaf.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial', '-out', 'leaf.pem', '-days', '1', '-extfile', 'leaf.ext');
fs.copyFileSync(`${tls}/ca.pem`, `${OUT}/ca.pem.tmp`);
fs.renameSync(`${OUT}/ca.pem.tmp`, `${OUT}/ca.pem`);

// Canary values only (fixture-safety EDR): a recognisable prefix the harness searches for.
let n = 0;
const v = () => `seclabcanary_value_${NONCE}_${n++}`;
const body = () => ({
	login: v(), copilot_plan: v(), access_type_sku: v(), analytics_tracking_id: v(), chat_enabled: true,
	endpoints: { api: `https://${v()}.example.test`, telemetry: `https://${v()}.example.test` },
	organization_login_list: [v(), v()], quota_snapshots: { chat: { remaining: 7, note: v() } },
	unmeasured_future_field: v(),
});

https.createServer({ key: fs.readFileSync(`${tls}/leaf.key`), cert: fs.readFileSync(`${tls}/leaf.pem`) }, (req, res) => {
	const p = (req.url ?? '').split('?')[0];
	if (req.method === 'GET' && (p === '/copilot_internal/user' || p === '/api/v3/copilot_internal/user')) {
		res.writeHead(200, { 'content-type': 'application/json' });
		res.end(JSON.stringify(body()));
		return;
	}
	res.writeHead(404);
	res.end();
}).listen(443);
