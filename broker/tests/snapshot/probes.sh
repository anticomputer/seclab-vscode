#!/bin/sh
# The snapshot writer's review probes (round 10b, finding 10b-1 and its siblings), replayed in
# CI against the real writer: broker/build.sh --write-context, under each shell in $SHELLS
# (dash, and bash in POSIX mode as macOS /bin/sh), with GNU ln. Each probe is a tree built with
# git plumbing, so it can hold what a checkout can't (duplicate names, a symlink named like a
# directory). Accepted trees must be written exactly (every entry, by object ID and mode, and
# nothing else); refused trees must fail and write nothing outside the context; nothing ever
# appears in the working directory. Runs in a throwaway container (broker/tests/snapshot/run.sh).
#   probes.sh BUILD_SH
set -eu
build_sh=$1
SHELLS=${SHELLS:-dash bash}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
repo=$work/repo
git init -q "$repo"
git -C "$repo" config user.email probe@invalid
git -C "$repo" config user.name probe
mkdir -p "$repo/broker"
cp "$build_sh" "$repo/broker/build.sh"
git -C "$repo" add broker/build.sh
git -C "$repo" commit -q -m probe
fails=0
fail() { echo "snapshot probes: FAIL [$1]: $2" >&2; fails=$((fails + 1)); }

blob() { printf %s "$1" | git -C "$repo" hash-object -w --stdin; }
# tree LINE...: each line "MODE TYPE OBJ<TAB>NAME"; no sorting or checks beyond git mktree's own.
tree() { printf '%s\n' "$@" | git -C "$repo" mktree --missing; }
T=$(printf '\t')

# Accepted: `-rf` and `-f` link targets (10b-1), a first path component starting with `-`
# (10b-3), an executable, and .gitattributes that git archive would honour (10-2).
attrs=$(blob '* export-ignore
*.txt text eol=crlf
')
lf=$(blob 'line one
line two
')
sub_n=$(tree "100644 blob $(blob dash-dir)${T}f.txt")
ok=$(tree \
  "100644 blob $attrs${T}.gitattributes" \
  "100644 blob $(blob 'FROM scratch')${T}Dockerfile" \
  "040000 tree $sub_n${T}-n" \
  "120000 blob $(blob -f)${T}link-f" \
  "120000 blob $(blob -rf)${T}link-rf" \
  "120000 blob $(blob Dockerfile)${T}link-rel" \
  "100755 blob $(blob '#!/bin/sh')${T}run.sh" \
  "100644 blob $lf${T}t.txt")

# Refused, each with a reason the writer prints.
esc_sub=$(tree "100644 blob $(blob escaped)${T}x")
esc=$(tree "120000 blob $(blob ../outside)${T}esc" "040000 tree $esc_sub${T}esc")
dsub=$(tree "100644 blob $(blob inner)${T}x")
filedir=$(tree "100644 blob $(blob file)${T}d" "040000 tree $dsub${T}d")
dup=$(tree "100644 blob $(blob one)${T}same" "100644 blob $(blob two)${T}same")
duplink=$(tree "100644 blob $(blob one)${T}same" "120000 blob $(blob elsewhere)${T}same")
empty=$(tree "120000 blob $(blob '')${T}empty-link")
nl=$(tree "120000 blob $(printf 'target\n' | git -C "$repo" hash-object -w --stdin)${T}nl-link")
gitlink=$(tree "160000 commit $(git -C "$repo" rev-parse HEAD)${T}sub")
quoted=$(tree "100644 blob $(blob q)${T}caf$(printf '\303\251').md")
dotdot=$(tree "100644 blob $(blob up)${T}..")

check_exact() {  # $1 shell, $2 tree, $3 context dir
  n=0
  git -C "$repo" ls-tree -r "$2" > "$work/list"
  while IFS= read -r e; do
    meta=${e%%"$T"*} p=${e#*"$T"}
    mode=${meta%% *} obj=${meta##* }
    n=$((n + 1))
    f=$3/$p
    case $mode in
      120000)
        [ -L "$f" ] || { fail "$1" "$p is not a symlink"; continue; }
        got=$(readlink -- "$f" | tr -d '\n' | git -C "$repo" hash-object --stdin) ;;
      *)
        [ -f "$f" ] && [ ! -L "$f" ] || { fail "$1" "$p is not a regular file"; continue; }
        got=$(git -C "$repo" hash-object --no-filters -- "$f")
        if [ "$mode" = 100755 ]; then [ -x "$f" ] || fail "$1" "$p lost its exec bit"
        else [ ! -x "$f" ] || fail "$1" "$p gained an exec bit"; fi ;;
    esac
    [ "$got" = "$obj" ] || fail "$1" "$p differs from the tree ($got != $obj)"
  done < "$work/list"
  have=$(find "$3" \( -type f -o -type l \) | wc -l | tr -d ' ')
  [ "$have" -eq "$n" ] || fail "$1" "context has $have entries, the tree $n"
}

for sh in $SHELLS; do
  case $sh in bash) run="bash --posix" ;; *) run=$sh ;; esac
  command -v "${run%% *}" >/dev/null || { fail "$sh" "shell not found"; continue; }
  cwd=$work/cwd-$sh
  mkdir -p "$cwd"

  if (cd "$cwd" && $run "$repo/broker/build.sh" --write-context "$ok" "$work/ok-$sh") 2>"$work/err"; then
    check_exact "$sh" "$ok" "$work/ok-$sh"
  else
    fail "$sh" "accepted tree refused: $(cat "$work/err")"
  fi

  for probe in "esc:$esc:collides" "filedir:$filedir:collides" "dup:$dup:collides" "duplink:$duplink:collides" \
               "empty:$empty:written exactly" "nl:$nl:written exactly" "gitlink:$gitlink:only files and symlinks" \
               "quoted:$quoted:refusing snapshot path" "dotdot:$dotdot:refusing snapshot path"; do
    name=${probe%%:*} rest=${probe#*:}
    t=${rest%%:*} why=${rest#*:}
    out=$work/$name-$sh
    if (cd "$cwd" && $run "$repo/broker/build.sh" --write-context "$t" "$out") 2>"$work/err"; then
      fail "$sh" "$name was accepted"
    elif ! grep -q "$why" "$work/err"; then
      fail "$sh" "$name refused without '$why': $(cat "$work/err")"
    fi
  done
  # Nothing outside a context: no escape target, no stray links in the working directory.
  [ ! -e "$work/outside" ] && [ ! -L "$work/outside" ] || fail "$sh" "something was written outside the context"
  [ -z "$(ls -A "$cwd")" ] || fail "$sh" "the working directory gained: $(ls -A "$cwd" | tr '\n' ' ')"
  [ -z "$(find "$work" -maxdepth 1 -name '*.list')" ] || fail "$sh" "a listing file was left behind"
done

[ "$fails" -eq 0 ] || exit 1
echo "snapshot probes: ok ($SHELLS; 1 exact tree, 9 refusals each; nothing written outside a context)"
