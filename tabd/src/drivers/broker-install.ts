// Getting the tab's broker into the tab (plan tabd-broker-wiring B1/B2): the proxy URL and the
// broker CA go into a root-owned directory that seclab-tab-env reads. Shared by the OCI and sbx
// drivers. Nothing tab- or broker-supplied is interpolated into the script: the URL and the PEM
// arrive on stdin, after validation here.

import type { BrokerSetup } from './types.ts';
import { DriverError } from './types.ts';

export const BROKER_DIR = '/run/seclab-broker';
const PEM_RE = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/;

/**
 * Root script: line 1 of stdin is the proxy URL, the rest the CA PEM. `mkdir` covers sbx (the
 * VM's /run); OCI mounts a root-owned tmpfs there. The directory must be a real directory,
 * root-owned, and not group/other-writable, or it is refused (review ZZ-4); stale `*.new`
 * entries are removed before writing.
 */
export const INSTALL_BROKER = `set -eu; umask 022; d=${BROKER_DIR}; mkdir -p "$d"
[ ! -L "$d" ] && [ -d "$d" ] && [ "$(stat -c %u "$d")" = 0 ] && [ $(( 0$(stat -c %a "$d") & 022 )) = 0 ] || { echo "broker dir is not a root-owned, non-writable directory" >&2; exit 1; }
rm -f "$d/ca.pem.new" "$d/bundle.pem.new" "$d/proxy-url.new"; IFS= read -r url; cat > "$d/ca.pem.new"
cat /etc/ssl/certs/ca-certificates.crt "$d/ca.pem.new" > "$d/bundle.pem.new"
printf '%s\\n' "$url" > "$d/proxy-url.new"
mv "$d/ca.pem.new" "$d/ca.pem"; mv "$d/bundle.pem.new" "$d/bundle.pem"; mv "$d/proxy-url.new" "$d/proxy-url"`;

/** Validated stdin for INSTALL_BROKER, with the proxy at `proxyHost` (host:port). */
export function brokerInstallInput(setup: BrokerSetup, proxyHost: string): string {
	if (!PEM_RE.test(setup.caPem) || !/^[A-Za-z0-9_-]{1,64}$/.test(setup.proxyUser) || !/^[A-Za-z0-9_-]{16,128}$/.test(setup.proxyPassword)
		|| !/^(broker:8080|host\.docker\.internal:[0-9]{1,5})$/.test(proxyHost)) {
		throw new DriverError(-32013, 'broker setup returned an invalid CA or proxy credential');
	}
	return `http://${setup.proxyUser}:${setup.proxyPassword}@${proxyHost}\n${setup.caPem}`;
}
