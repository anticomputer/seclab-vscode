"""Source tree access and permalink helpers.

Standard library only, on purpose: the generator runs in a stock, digest-pinned
Python container with no install step (see rpc-filter/tools/*.sh).
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Iterator

PERMALINK_BASE = "https://github.com/microsoft/vscode/blob"


@dataclass
class SourceTree:
    """A read-only checkout of upstream Code-OSS pinned at ``sha``."""

    root: str
    sha: str
    _cache: dict = field(default_factory=dict, repr=False)

    def path(self, rel: str) -> str:
        return os.path.join(self.root, rel)

    def exists(self, rel: str) -> bool:
        return os.path.isfile(self.path(rel))

    def lines(self, rel: str) -> list:
        """Read a file as a list of lines, cached. Missing files read as empty."""
        if rel not in self._cache:
            try:
                with open(self.path(rel), "r", encoding="utf-8", errors="replace") as fh:
                    self._cache[rel] = fh.read().splitlines()
            except OSError:
                self._cache[rel] = []
        return self._cache[rel]

    def text(self, rel: str) -> str:
        return "\n".join(self.lines(rel))

    def walk(self, subdir: str, suffixes: tuple = (".ts",)) -> Iterator:
        """Yield repo-relative paths under ``subdir`` with any of ``suffixes``.

        Test files and declaration files are skipped: they are not part of the
        shipped attack surface.

        Both ``dirnames`` and ``filenames`` are sorted. ``os.walk`` otherwise
        yields directories in filesystem order, which differs between macOS
        (APFS) and CI (ext4), so the generator would not be reproducible.
        ``dirnames`` is sorted *in place* because ``os.walk`` reads the same
        list back to decide what to descend into.
        """
        base = self.path(subdir)
        for dirpath, dirnames, filenames in os.walk(base):
            dirnames[:] = sorted(d for d in dirnames if d not in (
                "node_modules", ".git", "test", "__snapshots__"))
            for name in sorted(filenames):
                if not name.endswith(suffixes):
                    continue
                if name.endswith(".d.ts") or ".test." in name:
                    continue
                full = os.path.join(dirpath, name)
                yield os.path.relpath(full, self.root)

    def permalink(self, rel: str, line=None, end=None) -> str:
        url = "%s/%s/%s" % (PERMALINK_BASE, self.sha, rel)
        if line:
            url += "#L%d" % line
            if end and end != line:
                url += "-L%d" % end
        return url


def read_pinned_sha(repo_root: str, fallback: str) -> tuple:
    """Resolve the upstream SHA.

    Prefers ``upstream.lock`` (owned by the fork-build session) so the
    inventory follows the same pin as the build. Returns ``(sha, origin)``.
    """
    lock = os.path.join(repo_root, "upstream.lock")
    if os.path.isfile(lock):
        with open(lock, "r", encoding="utf-8") as fh:
            body = fh.read()
        match = re.search(r"\b([0-9a-f]{40})\b", body)
        if match:
            return match.group(1), "upstream.lock"
    return fallback, "fallback-constant"


def strip_block_comments(text: str) -> str:
    """Remove /* */ and // comments so declarations in comments are not matched."""
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"(?m)^\s*//.*$", "", text)
