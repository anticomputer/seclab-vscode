# seclab-wb-mount (review OR-R3): the workspace path resolves with no link at any step, and after
# mounting the host share's only mount point is the workspace path, under the overlay. In an sbx
# tab the workspace's parent belongs to the tab user (measured 2026-11-16), so a tab can rename it
# and move the share; the mount check catches that. No root needed; runs in ./seclab test unit.
#   python3 sandbox/test/test_wb_mount.py
import importlib.machinery
import importlib.util
import os
import shutil
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", "rootfs", "opt", "seclab", "bin", "seclab-wb-mount")
loader = importlib.machinery.SourceFileLoader("seclab_wb_mount", SCRIPT)
spec = importlib.util.spec_from_loader("seclab_wb_mount", loader)
wb = importlib.util.module_from_spec(spec)
loader.exec_module(wb)


class LinkProblem(unittest.TestCase):
    def setUp(self):
        self.base = os.path.realpath(tempfile.mkdtemp(prefix="seclab-wb-mount-"))
        os.makedirs(os.path.join(self.base, "a", "ws"))
        os.symlink(os.path.join(self.base, "a"), os.path.join(self.base, "link"))
        os.symlink(os.path.join(self.base, "a", "ws"), os.path.join(self.base, "a", "wslink"))

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_a_link_free_path_passes(self):
        self.assertIsNone(wb.link_problem(self.base + "/a/ws"))

    def test_a_symlinked_ancestor_is_refused(self):
        self.assertIn("following a link", wb.link_problem(self.base + "/link/ws"))

    def test_a_symlinked_workspace_is_refused(self):
        self.assertIn("following a link", wb.link_problem(self.base + "/a/wslink"))


WS = "/srv/tabs/parent/proj"
DEV = os.makedev(0, 61)


def info(mid, dev, point, fstype):
    return "%d 1 %s / %s rw,relatime shared:1 - %s src rw\n" % (mid, dev, point, fstype)


class ShareMountProblem(unittest.TestCase):
    def test_share_at_the_workspace_under_the_overlay_passes(self):
        lines = [info(30, "0:61", WS, "virtiofs"), info(40, "0:70", WS, "fuse.fuse-overlayfs")]
        self.assertIsNone(wb.share_mount_problem(lines, WS, DEV))

    def test_a_share_moved_by_renaming_a_tab_owned_ancestor_is_refused(self):
        # The tab renamed /srv/tabs/parent before the mount: the share now sits at the new name,
        # and the overlay landed on a decoy directory at the old path.
        lines = [info(30, "0:61", "/srv/tabs/parent-moved/proj", "virtiofs"), info(40, "0:70", WS, "fuse.fuse-overlayfs")]
        self.assertIn("not only at the workspace path", wb.share_mount_problem(lines, WS, DEV))

    def test_a_second_mount_of_the_share_is_refused(self):
        lines = [info(30, "0:61", WS, "virtiofs"), info(31, "0:61", "/mnt/x", "virtiofs"), info(40, "0:70", WS, "fuse.fuse-overlayfs")]
        self.assertIn("not only at the workspace path", wb.share_mount_problem(lines, WS, DEV))

    def test_no_overlay_on_the_workspace_is_refused(self):
        lines = [info(30, "0:61", WS, "virtiofs")]
        self.assertIn("no overlay", wb.share_mount_problem(lines, WS, DEV))

    def test_an_escaped_mount_point_is_compared_unescaped(self):
        ws = "/srv/tabs/parent/my proj"
        lines = [info(30, "0:61", "/srv/tabs/parent/my\\040proj", "virtiofs"), info(40, "0:70", "/srv/tabs/parent/my\\040proj", "fuse.fuse-overlayfs")]
        self.assertIsNone(wb.share_mount_problem(lines, ws, DEV))


if __name__ == "__main__":
    unittest.main()
