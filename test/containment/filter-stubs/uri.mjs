export class URI {
	constructor(c) {
		this.scheme = c.scheme ?? ''; this.authority = c.authority ?? ''; this.path = c.path ?? '';
		this.query = c.query ?? ''; this.fragment = c.fragment ?? '';
	}
	static revive(raw) { return raw && typeof raw === 'object' ? new URI(raw) : raw; }
	static from(c) { return new URI(c); }
	get fsPath() { return this.path; }
	toString() { return `${this.scheme}://${this.authority}${this.path}${this.query ? `?${this.query}` : ''}${this.fragment ? `#${this.fragment}` : ''}`; }
}
