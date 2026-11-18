// Upstream's vendored marked (SECLAB_MARKED), with a count of lexer runs, so a test can show that
// oversized tab markdown never reaches the lexer. Not a stand-in: every call goes to the real one.
const real = await import(new URL(`file://${process.env.SECLAB_MARKED}`).href);
export class Marked extends real.Marked {
	lexer(...args) {
		globalThis.seclabLexerRuns = (globalThis.seclabLexerRuns ?? 0) + 1;
		return super.lexer(...args);
	}
}
