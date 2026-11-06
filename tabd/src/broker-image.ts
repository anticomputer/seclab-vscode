// The broker image's identity (review XX-6). broker/build.sh stamps provenance labels on the
// image and prints its ID. tabd resolves the configured reference to that content-addressed ID
// at every tab start, checks the labels, and creates the broker by ID, so a retag between check
// and use changes nothing. Labels are self-asserted: they tell a build.sh build of a compatible broker apart
// from anything else (a stale or unlabelled build, another tool's image), not an attacker with
// docker access, who already controls the VM.

import type { Runner } from './run.ts';
import { BROKER_POLICY_SCHEMA, BROKER_PROTOCOL, REBUILD_HINT } from './broker.ts';

/** The verified mitmproxy base (broker/deps.json, images[name=mitmproxy/mitmproxy].ref after `@`). A unit test pins it. */
export const BROKER_BASE_DIGEST = 'sha256:2711066c855659b5af8b1dbb84494ed3eff69b42ece439c60b4fe09a2db829d4';

export const BROKER_LABELS = {
	revision: 'org.opencontainers.image.revision',
	base: 'org.opencontainers.image.base.digest',
	version: 'org.opencontainers.image.version',
	protocol: 'io.seclab.broker.protocol',
	policyRevision: 'io.seclab.broker.policy-revision',
} as const;

export interface BrokerImage {
	/** `docker image inspect` `.Id`: what every broker container is created from. */
	readonly id: string;
	readonly revision: string;
	/** The broker version the image declares; `broker.hello` must report the same. */
	readonly version: string;
}

/** Check an image's ID and labels; returns the problems (empty when acceptable). */
export function brokerImageProblems(id: string, labels: Record<string, string> | null, opts: { allowDirty: boolean }): string[] {
	const p: string[] = [];
	if (!/^sha256:[0-9a-f]{64}$/.test(id)) {
		p.push(`image id ${JSON.stringify(id.slice(0, 80))} is not a sha256 digest`);
	}
	const l = labels ?? {};
	if (l[BROKER_LABELS.base] !== BROKER_BASE_DIGEST) {
		p.push(`base ${JSON.stringify(l[BROKER_LABELS.base] ?? null)} is not the verified mitmproxy digest`);
	}
	if (l[BROKER_LABELS.protocol] !== BROKER_PROTOCOL) {
		p.push(`protocol ${JSON.stringify(l[BROKER_LABELS.protocol] ?? null)}, expected ${BROKER_PROTOCOL} (${REBUILD_HINT})`);
	}
	if (l[BROKER_LABELS.policyRevision] !== String(BROKER_POLICY_SCHEMA.revision)) {
		p.push(`policy revision ${JSON.stringify(l[BROKER_LABELS.policyRevision] ?? null)}, expected ${BROKER_POLICY_SCHEMA.revision} (${REBUILD_HINT})`);
	}
	if (!/^[0-9]+\.[0-9]+\.[0-9]+$/.test(l[BROKER_LABELS.version] ?? '')) {
		p.push(`version ${JSON.stringify(l[BROKER_LABELS.version] ?? null)} is not a release version`);
	}
	const rev = l[BROKER_LABELS.revision] ?? '';
	const m = rev.match(/^[0-9a-f]{40}(-dirty)?$/);
	if (!m) {
		p.push(`revision ${JSON.stringify(rev || null)} is not a git commit`);
	} else if (m[1] && !opts.allowDirty) {
		p.push(`revision ${rev} was built from uncommitted broker sources (rebuild from a clean tree, or run tabd with --broker-dev)`);
	}
	return p;
}

/**
 * Resolves and checks the configured broker image. Resolved at every tab start, not cached:
 * a rebuilt broker reaches new tabs without restarting tabd, and a pruned old ID can't strand
 * it (ZZ-10). Creating by the returned ID leaves no window for a retag to swap the image.
 */
export class BrokerImagePin {
	private readonly runner: Runner;
	private readonly docker: string;
	private readonly ref: string;
	private readonly allowDirty: boolean;

	constructor(runner: Runner, docker: string, ref: string, opts: { allowDirty?: boolean } = {}) {
		this.runner = runner;
		this.docker = docker;
		this.ref = ref;
		this.allowDirty = opts.allowDirty ?? false;
	}

	get(): Promise<BrokerImage> {
		return this.resolve();
	}

	private async resolve(): Promise<BrokerImage> {
		const r = await this.runner.run(this.docker, ['image', 'inspect', '--format', '{{json .Id}}\n{{json .Config.Labels}}', '--', this.ref], { timeoutMs: 30_000 });
		if (r.code !== 0) {
			throw new Error(`broker image ${this.ref} unavailable (run ./seclab image oci)`);
		}
		let id = '';
		let labels: Record<string, string> | null = null;
		try {
			const [a, b] = r.stdout.trim().split('\n');
			id = JSON.parse(a) as string;
			labels = JSON.parse(b) as Record<string, string> | null;
		} catch {
			throw new Error(`broker image ${this.ref}: unreadable inspect output`);
		}
		const problems = brokerImageProblems(typeof id === 'string' ? id : '', labels && typeof labels === 'object' ? labels : null, { allowDirty: this.allowDirty });
		if (problems.length) {
			throw new Error(`broker image ${this.ref} refused (rebuild with ./seclab image oci): ${problems.join('; ')}`);
		}
		return { id, revision: labels![BROKER_LABELS.revision], version: labels![BROKER_LABELS.version] };
	}
}
