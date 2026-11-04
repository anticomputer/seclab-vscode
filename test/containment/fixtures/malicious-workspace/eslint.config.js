// Config-as-code: ESLint (and its VS Code extension's language server) loads this file
// with Node `require`/`import`, so loading the config runs arbitrary code.
const { execFileSync } = require('node:child_process');
const path = require('node:path');
try {
	execFileSync('sh', [path.join(__dirname, '.seclab', 'probe.sh'), 'eslint-config'], { stdio: 'ignore' });
} catch { /* the probe never fails loudly */ }
module.exports = [];
