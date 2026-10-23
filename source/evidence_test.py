"""
End-to-end check of the 'evidence' command, without crash.

Runs evidence.py under a stand-in pykdump (canned 'sys', 'bt', 'log' ...)
with stand-in pycrashext commands, in a temporary directory, and checks the
file it writes: where it goes, the branch it picked, the follow-ups it ran,
the Source lines, and the true '<<< SKIPPED N lines >>>' counts.

Run directly: python3 source/evidence_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

FAKE_API = r'''
import os, re
from optparse import OptionParser

ROOT = os.environ["EV_ROOT"]
LOG = "\n".join(["[%8.6f] filler line %d" % (i, i) for i in range(400)] + [
    "[ 900.000000] BUG: unable to handle kernel NULL pointer dereference at 0000000000000008",
    "[ 900.000001] RIP: 0010:foo_bar+0x15/0x40 [mydrv]",
    "[ 900.000002] Kernel panic - not syncing: Fatal exception"])
OUT = {
    "sys": """      KERNEL: /usr/lib/debug/vmlinux
    DUMPFILE: %s/cores/tasks/886244457/crash/vmcore  [PARTIAL DUMP]
        CPUS: 8
    NODENAME: host1.example.com
     RELEASE: 4.18.0-553.el8_10.x86_64
       PANIC: "BUG: unable to handle kernel NULL pointer dereference at 0000000000000008"
""" % ROOT,
    "bt": """PID: 1234     TASK: ffff8c1a2b3c4d00  CPU: 3    COMMAND: "kworker/3:1"
 #7 [ffffa1b2c3d4e230] page_fault at ffffffff8ac0111e
    [exception RIP: foo_bar+21]
    RIP: ffffffffc0a1b2c5  RSP: ffffa1b2c3d4e2e8  RFLAGS: 00010246
 #8 [ffffa1b2c3d4e2f0] foo_bar at ffffffffc0a1b2c5 [mydrv]
""",
    "log": LOG,
    "mod -t": "NAME    TAINTS\nmydrv   OE",
    "kmem -i": "                 PAGES        TOTAL      PERCENTAGE\n    TOTAL MEM  4000000      15.3 GB         ----",
    "ps -S": "  RU: 9\n  IN: 400\n  UN: 2",
    "sym ffffffffc0a1b2c5": "ffffffffc0a1b2c5 (t) foo_bar+21 [mydrv] /usr/src/debug/mydrv/foo.c: 42",
}

def exec_crash_command(cmd):
    if cmd in OUT:
        return OUT[cmd]
    if cmd == "foreach UN bt":
        raise Exception("")  # pykdump raises on empty output
    raise Exception("crash: command failed: %s" % cmd)
'''

# Stand-ins for the pycrashext commands 'evidence' runs in-process. Each
# prints what its alias would, including colour codes for edis.
FAKE_CMDS = {
    "caseinfo": 'print(" Case No: 04517832, Hostname: host1.example.com")',
    "sysinfo": 'print("SYSINFO platform=vmware rhel=8.10 cpus=8 mem=16G taint=OE")',
    "autocheck": 'print("autocheck: no known issue matched")',
    "edis": ('import sys\n'
             'assert sys.argv[1:] == ["-r", "ffffffffc0a1b2c5"], sys.argv\n'
             'for i in range(100): print("\\x1b[1;32m0xffffffffc0a1b2%02x <foo_bar+%d>:\\x1b[0m mov %%rax,%%rbx" % (i, i))'),
    "modinfo": 'import sys\nprint("module %s: OE, /lib/modules/extra/mydrv.ko" % sys.argv[-1])',
    "kvercmp": 'import sys\nprint("KVERCMP verdict=NOT_FIXED %s" % " ".join(sys.argv[1:]))',
}


def setup(root):
    os.makedirs(os.path.join(root, "pykdump"))
    with open(os.path.join(root, "pykdump", "__init__.py"), "w") as f:
        f.write("")
    with open(os.path.join(root, "pykdump", "API.py"), "w") as f:
        f.write(FAKE_API)
    src = os.path.join(root, "src")
    os.makedirs(src)
    for name in ("evidence.py", "evidplan.py", "logsig.py", "logscan.py"):
        shutil.copy(os.path.join(HERE, name), src)
    for name, body in FAKE_CMDS.items():
        with open(os.path.join(src, name + ".py"), "w") as f:
            f.write(body + "\n")
    task = os.path.join(root, "cores", "tasks", "886244457")
    os.makedirs(task)
    with open(os.path.join(task, "caseno"), "w") as f:
        f.write("04517832\n")
    os.makedirs(os.path.join(root, "home"))
    return src


def run(root, src, *args):
    env = dict(os.environ, EV_ROOT=root, HOME=os.path.join(root, "home"),
               PYTHONPATH=root + os.pathsep + src)
    p = subprocess.run([sys.executable, os.path.join(src, "evidence.py")] + list(args),
                       cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                       universal_newlines=True)
    return p.returncode, p.stdout


def main():
    root = tempfile.mkdtemp(prefix="evidence-test.")
    try:
        src = setup(root)
        rc, out = run(root, src, "-q")
        assert rc == 0, out
        path = os.path.join(root, "home", "cases", "04517832", "vmcore-886244457-evidence.md")
        assert ("EVIDENCE file=%s task=886244457 case=04517832 branches=A" % path) in out, out
        doc = open(path).read()
        # Header and derived summary.
        assert doc.startswith("# VMCORE EVIDENCE — task `886244457`"), doc[:200]
        assert "**Case Number:** `04517832`" in doc
        assert "Fault:** foo_bar+21 [mydrv] in pid 1234 (kworker/3:1) on CPU 3" in doc
        # Base, branch and follow-up commands, each under its Source line.
        for cmd in ("sys", "caseinfo", "logscan", "log", "edis -r ffffffffc0a1b2c5",
                    "sym ffffffffc0a1b2c5", "modinfo --details mydrv"):
            assert "**Source:** `/cores/tasks/886244457` → `%s`" % cmd in doc, cmd
        # The real logscan ran in-process against the canned log.
        assert "oops" in doc and "== oops:" in doc
        # The log keeps its last 150 lines; the count is the real one.
        assert "<<< SKIPPED 253 lines >>>\n[253.000000] filler line 253" in doc, doc[doc.find("Kernel log"):][:400]
        # edis: colour removed, last 70 of 100 lines kept.
        assert "\x1b[" not in doc
        assert "<<< SKIPPED 30 lines >>>\n0xffffffffc0a1b21e <foo_bar+30>:" in doc
        # A command crash rejects is recorded, not fatal.
        assert "autocheck" in doc and "## Evidence" in doc
        # Follow-ups appended with -a.
        rc, out = run(root, src, "-q", "-a", "-x",
                      "log | grep -i panic; log | wc -l; bt | awk x; kvercmp kernel-4.18.0-600.el8; foreach UN bt; log | grep (x")
        assert rc == 0, out
        doc2 = open(path).read()
        assert doc2.startswith(doc.rstrip("\n")), "append changed the original blocks"
        assert "`log | grep -i panic`" in doc2 and "Kernel panic - not syncing: Fatal exception" in doc2
        assert "~~~\n403\n~~~" in doc2
        assert "'| awk x' is not run here" in doc2
        # A pycrashext command outside the fixed list runs in-process too.
        assert "KVERCMP verdict=NOT_FIXED kernel-4.18.0-600.el8" in doc2
        # Empty output is not a failure; a bad pattern fails one block only.
        un = doc2[doc2.index("Follow-up: foreach UN bt"):]
        assert un.split("###")[0].count("error") == 0 and "> (no output)" in un, un[:300]
        assert "Follow-up: log | grep (x" in doc2
        # No case number: the file goes to ~/cases/vmcores/<task>/.
        os.remove(os.path.join(root, "cores", "tasks", "886244457", "caseno"))
        rc, out = run(root, src, "-q")
        assert rc == 0, out
        path3 = os.path.join(root, "home", "cases", "vmcores", "886244457", "vmcore-886244457-evidence.md")
        assert ("EVIDENCE file=%s task=886244457 case=unknown" % path3) in out, out
        print("evidence: end-to-end checks passed (%d bytes written)" % len(doc2))
    finally:
        shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    main()
