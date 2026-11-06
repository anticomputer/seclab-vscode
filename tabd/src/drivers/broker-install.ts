// Getting the tab's broker into the tab (plan tabd-broker-wiring B1/B2): the proxy URL and the
// broker CA go into a root-owned directory that seclab-tab-env reads. Shared by the OCI and sbx
// drivers. Nothing tab- or broker-supplied is interpolated into the script: the URL and the PEM
// arrive on stdin, after validation here.

import type { BrokerImage, BrokerImagePin } from '../broker-image.ts';
import { CFS_HOST, CFS_NPM_PATH, CFS_PYPI_PATH, feedInstallLine } from '../cfs.ts';
import type { Runner } from '../run.ts';
import type { BrokerSetup } from './types.ts';
import { DriverError } from './types.ts';

/** The checked broker image (XX-6), as a driver error when it is missing or refused. */
export async function pinnedBrokerImage(pin: BrokerImagePin | undefined): Promise<BrokerImage> {
	if (!pin) {
		throw new DriverError(-32011, 'the template requires a broker, but no broker image was configured');
	}
	return pin.get().catch((e: Error) => {
		throw new DriverError(-32011, e.message);
	});
}

/** A local image reference's ID (`docker image inspect .Id`), never pulling. */
export async function resolveImageId(runner: Runner, docker: string, ref: string): Promise<string> {
	const r = await runner.run(docker, ['image', 'inspect', '--format', '{{.Id}}', '--', ref], { timeoutMs: 30_000 });
	const id = r.stdout.trim();
	if (r.code !== 0 || !/^sha256:[0-9a-f]{64}$/.test(id)) {
		throw new DriverError(-32011, `image ${ref} unavailable (run ./seclab image oci)`);
	}
	return id;
}

/**
 * The tab's broker container, as found: absent, or its image ID. Throws when it exists but
 * isn't this tab's (another label: refuse, never remove), or when docker can't say (ZZ-8:
 * a failed inspect is never read as "absent").
 */
async function brokerContainer(runner: Runner, docker: string, name: string, tabId: string): Promise<{ image: string } | undefined> {
	const r = await runner.run(docker, ['container', 'inspect', '--format', '{{.Image}}|{{index .Config.Labels "seclab.tab"}}', '--', name], { timeoutMs: 15_000 });
	if (r.code !== 0) {
		if (/no such (object|container)/i.test(r.stderr)) {
			return undefined;
		}
		throw new DriverError(-32011, `could not inspect the broker container: ${r.stderr.trim().slice(-300)}`);
	}
	const [image, label] = r.stdout.trim().split('|');
	if (label !== tabId) {
		throw new DriverError(-32011, `container ${name} is not this tab's broker (label ${JSON.stringify(label)}); refusing to use or remove it`);
	}
	return { image };
}

/**
 * Remove the tab's broker container if it was created from another image than `imageId` (a
 * rebuilt broker, the placeholder, or a container from before XX-6), so it is recreated by ID.
 * The broker holds no state tabd needs: every start re-runs its whole bring-up. `-v` also
 * removes the anonymous volume the mitmproxy base declares.
 */
export async function dropBrokerFromOtherImage(runner: Runner, docker: string, name: string, tabId: string, imageId: string): Promise<void> {
	const c = await brokerContainer(runner, docker, name, tabId);
	if (c && c.image !== imageId) {
		const d = await runner.run(docker, ['rm', '-f', '-v', '--', name], { timeoutMs: 60_000 });
		if (d.code !== 0) {
			throw new DriverError(-32011, `could not replace the broker built from another image: ${d.stderr.trim().slice(-300)}`);
		}
	}
}

/** The tab's broker exists, is this tab's, and runs `imageId`; else the problem (ZZ-7, ZZ-8). */
export async function brokerImageProblem(runner: Runner, docker: string, name: string, tabId: string, imageId: string): Promise<string | undefined> {
	try {
		const c = await brokerContainer(runner, docker, name, tabId);
		if (!c) {
			return 'broker container missing';
		}
		return c.image === imageId ? undefined : `broker runs image ${c.image.slice(0, 19)}…, not the checked ${imageId.slice(0, 19)}…`;
	} catch (e) {
		return (e as Error).message;
	}
}

export const BROKER_DIR = '/run/seclab-broker';
const PEM_RE = /^-----BEGIN CERTIFICATE-----\r?\n[A-Za-z0-9+/=\r\n]+-----END CERTIFICATE-----\r?\n?$/;

// Root-only directory check, shared by both scripts (review ZZ-4).
const CHECK_DIR = `d=${BROKER_DIR}; mkdir -p "$d"
[ ! -L "$d" ] && [ -d "$d" ] && [ "$(stat -c %u "$d")" = 0 ] && [ $(( 0$(stat -c %a "$d") & 022 )) = 0 ] || { echo "broker dir is not a root-owned, non-writable directory" >&2; exit 1; }`;

/**
 * CFS package feeds (ADR cfs-package-feeds-in-tabs): from a `feed <sentinel> <base64>` or
 * `feed -` line, write (or remove) the tab's npm user config and pip index URL. The feed URLs
 * are fixed here, never from input; only the broker's sentinel goes in, never the token.
 * seclab-tab-env points npm (NPM_CONFIG_GLOBALCONFIG) and pip (PIP_INDEX_URL) at them.
 */
const npmFeed = `https://${CFS_HOST}${CFS_NPM_PATH}`;
const npmKey = `//${CFS_HOST}${CFS_NPM_PATH}`;
const WRITE_FEED = `IFS=' ' read -r tag fs fb; [ "$tag" = feed ] || { echo "bad feed line" >&2; exit 1; }
rm -f "$d/npmrc.new" "$d/pip-index-url.new"
if [ "$fs" = - ]; then rm -f "$d/npmrc" "$d/pip-index-url"; else
case "$fs$fb" in *[!A-Za-z0-9_.~=+/-]*|"") echo "bad feed sentinel" >&2; exit 1 ;; esac
printf 'registry=${npmFeed}\\n${npmKey}:username=cfs\\n${npmKey}:_password=%s\\n${npmKey}:always-auth=true\\n' "$fb" > "$d/npmrc.new"
printf 'https://cfs:%s@${CFS_HOST}${CFS_PYPI_PATH}simple/\\n' "$fs" > "$d/pip-index-url.new"
mv "$d/npmrc.new" "$d/npmrc"; mv "$d/pip-index-url.new" "$d/pip-index-url"; fi`;

/**
 * Root script: line 1 of stdin is the proxy URL, line 2 the feed line, the rest the CA PEM.
 * `mkdir` covers sbx (the VM's /run); OCI mounts a root-owned tmpfs there. The directory must
 * be a real directory, root-owned, and not group/other-writable, or it is refused (review
 * ZZ-4); stale `*.new` entries are removed before writing.
 */
export const INSTALL_BROKER = `set -eu; umask 022; ${CHECK_DIR}
rm -f "$d/ca.pem.new" "$d/bundle.pem.new" "$d/proxy-url.new"; IFS= read -r url
${WRITE_FEED}
cat > "$d/ca.pem.new"
cat /etc/ssl/certs/ca-certificates.crt "$d/ca.pem.new" > "$d/bundle.pem.new"
printf '%s\\n' "$url" > "$d/proxy-url.new"
mv "$d/ca.pem.new" "$d/ca.pem"; mv "$d/bundle.pem.new" "$d/bundle.pem"; mv "$d/proxy-url.new" "$d/proxy-url"`;

/** Root script for a running tab: one feed line on stdin (`tab.packages.set`). */
export const INSTALL_FEED = `set -eu; umask 022; ${CHECK_DIR}
${WRITE_FEED}`;

/** Validated stdin for INSTALL_BROKER, with the proxy at `proxyHost` (host:port). */
export function brokerInstallInput(setup: BrokerSetup, proxyHost: string): string {
	if (!PEM_RE.test(setup.caPem) || !/^[A-Za-z0-9_-]{1,64}$/.test(setup.proxyUser) || !/^[A-Za-z0-9_-]{16,128}$/.test(setup.proxyPassword)
		|| !/^(broker:8080|host\.docker\.internal:[0-9]{1,5})$/.test(proxyHost)) {
		throw new DriverError(-32013, 'broker setup returned an invalid CA or proxy credential');
	}
	return `http://${setup.proxyUser}:${setup.proxyPassword}@${proxyHost}\n${feedLine(setup.feedSentinel)}\n${setup.caPem}`;
}

/** The feed line for INSTALL_BROKER / INSTALL_FEED. */
export function feedLine(sentinel: string | undefined): string {
	try {
		return feedInstallLine(sentinel);
	} catch {
		throw new DriverError(-32013, 'broker setup returned an invalid package feed sentinel');
	}
}
