// Loopback-only recorder that plays the tab's broker for one question: does the agent
// runtime send its traffic to HTTPS_PROXY, and does it trust the per-tab CA we hand it?
// It answers CONNECT with 200, terminates TLS with a leaf issued by a per-run test CA,
// and records the outcome. It never forwards anything (the container has no network).
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as tls from 'node:tls';

const [port, keyFile, certFile, outFile] = process.argv.slice(2);
const events = [];
const save = () => fs.writeFileSync(outFile, JSON.stringify(events, null, 1));
const server = net.createServer(sock => {
	sock.once('data', buf => {
		const head = buf.toString('latin1');
		const m = /^CONNECT ([^\s:]+):(\d+) HTTP\/1\.[01]/.exec(head);
		if (!m) {
			events.push({ kind: 'non-connect', firstLine: head.split('\r\n')[0].slice(0, 200) });
			save();
			sock.end('HTTP/1.1 400 Bad Request\r\n\r\n');
			return;
		}
		const ev = { kind: 'connect', host: m[1], port: Number(m[2]) };
		events.push(ev);
		sock.write('HTTP/1.1 200 Connection Established\r\n\r\n');
		const t = new tls.TLSSocket(sock, { isServer: true, key: fs.readFileSync(keyFile), cert: fs.readFileSync(certFile) });
		t.on('secure', () => { ev.tls = 'handshake-ok'; save(); });
		t.once('data', d => {
			const text = d.toString('latin1');
			ev.request = text.split('\r\n')[0].slice(0, 200);
			const auth = /\r\nauthorization:\s*(\S+)\s+(\S+)/i.exec(text);
			ev.authScheme = auth?.[1];
			ev.authIsSentinel = !!auth && auth[2] === process.env.SENTINEL;
			save();
			t.end('HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n');
		});
		t.on('error', e => { ev.tls = `error: ${e.code ?? ''} ${e.message}`.slice(0, 200); save(); });
		save();
	});
	sock.on('error', () => { /* client aborts are recorded on the TLS socket */ });
});
server.listen(Number(port), '127.0.0.1', () => { fs.writeFileSync(outFile, '[]'); });
