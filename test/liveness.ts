// Liveness marks (EDR 20261109-liveness-gate): a runner records that it saw a subject run, at the
// point where it has evidence of that (not where it merely started it). CI sets
// SECLAB_LIVENESS_LOG for the job, and its last step, `./seclab liveness marks`, fails the job if
// a subject the register assigns to it left no mark. Elsewhere this does nothing.

import * as fs from 'node:fs';

export function liveMark(mark: string): void {
	const log = process.env.SECLAB_LIVENESS_LOG;
	if (log) {
		fs.appendFileSync(log, `${mark}\n`);
	}
}
