# Write-back gate spike: keeping tab writes to code-running files off the host

- **Status:** accepted (spike result; the design goes to an ADR)
- **Date:** 2026-11-04
- **Deciders:** anticomputer ("Watch and warn: the supervisor flags any change a tab makes to files that run code … and requires approval before that file goes live in your real checkout"); fork-build session
- **Related:** [ADR defeat folder-open loaders](../adr/20261104-defeat-folder-open-loaders.md), [EDR automatic-tasks-off](20261104-automatic-tasks-off.md)

## Question
The tab mounts the workspace read-write, so a payload can plant host-executed code
(`.git/hooks/*`, `.git/config` `core.fsmonitor`, `.envrc`, `package.json` scripts,
`Makefile`, …) that runs the next time the user uses git, direnv or npm in a **host**
terminal. The requirement is that unapproved content is never live in the host
checkout, not even briefly. Detect-and-revert is acceptable only as a documented fallback.

## Experiments (sbx 0.51, guest kernel 7.0.14; Docker Desktop 29.8)
| # | Setup | Result |
|---|---|---|
| 1 | sbx: workspace as an extra `PATH:/seclab/host-ro:ro` mount | The primary workspace must be read-write (`sbx create` refuses `:ro` for it); extra mounts can be read-only, and writes there fail with `EROFS`. |
| 2 | sbx: kernel `overlay` (lower = read-only mount, upper = VM-private `/run`) mounted as root | Mounts. As root: the tab's writes (`a.txt`, a new `.git/hooks/pre-commit`) land only in the upper layer; the host files are untouched; host-side changes (a new `b.txt`) show through. |
| 3 | sbx: the same, writing as the tab user (`agent`, uid 1000) | **Denied.** virtiofs presents host files as uid 0. Plain virtiofs writes work because permissions are enforced by the virtiofs server, but overlayfs checks the lower inode's root ownership itself. |
| 4 | sbx: idmapped lower (`mount_setattr` `MOUNT_ATTR_IDMAP`, 0→1000) under the overlay | `EINVAL`: sbx's virtiofs doesn't offer idmapped mounts. |
| 5 | sbx: overlay or bind mounts don't survive a sandbox stop/start | They must be set up on every start, as root, **before** the REH starts (the same slot as the observability collector). |
| 6 | sbx: FUSE in the VM | `/dev/fuse` is present and `fuse` is registered; the template is Debian trixie, which packages `fuse-overlayfs` (with `uidmapping`/`gidmapping`). |
| 7 | OCI: Docker `local` volume driver with `type=overlay` (lower = the host path in the Docker VM, upper = a Docker volume) | Mounts with `--cap-drop ALL`. On Docker Desktop the lower is root-owned (`/host_mnt`), so the uid-1000 tab can't write, as in experiment 3. On native Linux, where CI runs, the tab runs as the workspace owner (EDR oci-tab-user-on-linux), so ownership matches. |

## Findings
- **Not feasible:**
  - read-only sub-mounts over the sensitive paths alone: writes fail, which breaks git and `npm install` (they rewrite `package.json`), and there is nothing to show as a diff;
  - kernel overlay as the tab user on virtiofs (experiment 3);
  - idmapped mounts on sbx (experiment 4).
- **Feasible, sbx:** a **VM-private overlay with uid mapping**: `fuse-overlayfs`, lower = the host workspace (read-only extra mount), upper = VM-private, `uidmapping` 0→agent. It is mounted as root at the workspace's absolute path before the REH, and the original mount is hidden underneath. Every tab write lands in the upper layer, never on the host. A **write-back engine** in tabd then:
  - copies upper-layer changes (including whiteouts and renames) back to the host checkout;
  - does this immediately for ordinary files;
  - for files on the reviewed code-running list, holds the change and prompts with the diff, attributed to the tab;
  - on approval, writes to the host;
  - on rejection, restores the host version into the tab view.
- **Feasible, OCI on native Linux:** the same engine over a Docker `local` overlay volume (experiment 7). Docker Desktop needs `fuse-overlayfs` in a helper too (experiment 7's ownership issue); until then OCI on Desktop is a development driver without the gate.
- **`sbx --clone`** (a private in-VM git clone, with commits pulled back from a `sandbox-<name>` remote) also keeps the host untouched. But unsaved and uncommitted edits never reach the host, which changes the editing UX the user chose to keep. It is rejected as the default and could be a "strict" mode.

## Costs and open questions (for the ADR)
- **Host-side changes don't raise inotify events in the merged view.** A host `git pull` might not refresh the editor until the next access. This needs a measurement with `fuse-overlayfs`; the fallback is the REH's polling watcher for the workspace.
- **Conflicts:** a file both the host and the tab changed. Policy: the tab's view wins inside the tab, and the host keeps its version until the user resolves it in the prompt.
- **The write-back engine is new code** on the trust boundary. It parses an attacker-controlled upper layer (paths, symlinks, whiteouts, xattrs), so it needs the same hardening as the scanner (`O_NOFOLLOW`, no `..`, size caps) and a review round.
- **The primary sbx workspace must be read-write.** It becomes an empty per-tab scratch dir that nothing on the host reads.
- **Detect-and-revert** (host FSEvents on the sensitive paths, restore from a shadow copy) stays as the documented fallback for drivers without the overlay. It has a race window.

## Addendum 2026-11-05: fuse-overlayfs in sbx (increment 2 spike)
fuse-overlayfs 1.14 (Debian trixie debs fetched with apt in the pinned debian image, since sbx's
global policy blocks deb.debian.org), mounted by root over the workspace path with the same path
as its lower layer, `upperdir`/`workdir` under root-only `/var/lib/seclab/wb`, `allow_other`,
`squash_to_uid=1000,squash_to_gid=1000`:
- **Works:**
  - the tab user sees and edits the workspace as `agent`; edits land only in the upper layer,
    and the host file is unchanged;
  - the tab user can't unmount it (`fusermount3 -u`: not permitted) or list the upper/work dirs;
  - with `timeout=0` (fuse-overlayfs then reloads directories on every lookup, and the kernel
    entry/attribute timeouts are 0), files the host creates or deletes show through;
  - rewriting an upper file's **content** in place under the live mount is visible.
- **Unsafe:** removing an entry from the upper layer under the live mount made that path
  return ENOENT and later emptied the directory listing. Never change the upper layer's
  directory structure while mounted.
- **Without `timeout=0`:** host-side creates never appear (layer trees are cached).
- **The tab user owns `/dev/fuse`** (0600, `agent`) in the shell kit, so it can mount its own
  FUSE filesystems inside its VM. That only affects its own view; noted for the threat model.
- **No `mount` binary** in the kit; the overlay is mounted by fuse-overlayfs itself.

Consequence for the design (ADR write-back-gate, increment 2): an applied file stays in the
upper layer; a later host edit is mirrored into that upper copy in place while the tab hasn't
changed it (otherwise it is a conflict); entries identical to the host are pruned from the
upper layer only at tab start, before the mount (overlay mounts don't survive stop/start). A
process with a working directory inside the workspace from before the mount would see the
lower layer, so the mount must precede every tab process (the collector mounts first).

### Upper-layer format (2026-11-05, for increment 2b)
Observed with fuse-overlayfs 1.14 as root:
- a deleted lower file becomes an empty root-owned `.wh.<name>` file in the upper layer;
- a deleted and re-created directory gets `.wh..wh..opq`, meaning every lower child is hidden;
- a rename is a copy-up of the new name plus a whiteout of the old one;
- symlinks and modes are stored as-is.

A tab can't forge either marker: creating `.wh.x` or `.wh..wh..opq` through the overlay fails
with EINVAL. The feed can therefore treat them as the tab's deletions. Applied entries stay in
the upper layer (removal under a live mount is unsafe), so 2b mirrors later host edits into the
upper copy in place while the tab hasn't changed it; host-side deletions of such files are not
reflected until the next tab start.
