"""
'evidence' command: collect, in one crash session, the raw output a vmcore
analysis rests on, into one file an AI or an engineer writes the report from.

It runs what the /vmcore skill's phases would run, without a model choosing
each command: the base set every dump gets (sys, caseinfo, sysinfo, bt,
logscan, the end of the log, tainted modules, memory, task states,
autocheck), then the branch the crash calls for (panic/oops, OOM,
hang/lockup/stall, sysrq, death of init) with follow-ups taken from what it
already saw (the faulting function, its module, the faulting address), and
the hypervisor overcommit check on a hung VM. Each output goes into the file
under its Source line, exactly as printed, cut when long to its first and
last lines with a '<<< SKIPPED N lines >>>' line carrying the true count.

    evidence                      collect; write the file, print where
    evidence -o FILE              write it there
    evidence -x "bt 1234; struct mutex ffff9c..."   also run these commands
    evidence -a -x "..."          only run these, appended to the file
    evidence -f FILE              commands to run, one per line (with -a too)
    evidence --stdout             print the file instead of writing it

The file goes to ~/gemini/<case>/vmcore-<task>-evidence.md when the case is
known (from the task's 'caseno', the way 'caseinfo' finds it), else to the
current directory, else $HOME. The last line printed, "EVIDENCE file=...
task=... case=... branches=... blocks=... bytes=...", is for scripts.

What to run, and the layout, are in evidplan.py (checks in evidplan_test.py).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

import io
import os
import runpy
import signal
import sys
import time

import evidplan


def find_module(name):
    """Path of a pycrashext command's .py file, or None."""
    dirs = []
    here = globals().get("__file__")
    if here:
        dirs.append(os.path.dirname(os.path.abspath(here)))
    dirs.extend(p for p in sys.path if p)
    for d in os.environ.get("PYKDUMPPATH", "").split(":"):
        if d:
            dirs.append(d)
    for d in dirs:
        p = os.path.join(d, name + ".py")
        if os.path.isfile(p):
            return p
    return None


def is_pycrashext(name):
    """A pycrashext command: a known one, or any command file beside this
    one (git, kvercmp, insights ...). crash's own commands have no file
    here."""
    if name in evidplan.PYCRASHEXT:
        return True
    here = globals().get("__file__")
    if not here or name.endswith("_test") or name in evidplan.HELPERS:
        return False
    return os.path.isfile(os.path.join(os.path.dirname(os.path.abspath(here)), name + ".py"))


def run_pycrashext(name, args):
    """Run a pycrashext command in this process, as crash would, and return
    (output, error): its file runs as __main__ with the arguments in
    sys.argv and its output captured, instead of starting a nested epython
    through exec_crash_command."""
    path = find_module(name)
    if not path:
        return "", "pycrashext command '%s' not found" % name
    out, err = io.StringIO(), io.StringIO()
    saved = sys.argv, sys.stdout, sys.stderr
    # A command may install its own SIGINT handler (autocheck's exits 0):
    # put the session's back so Ctrl-C still stops 'evidence'.
    try:
        sigint = signal.getsignal(signal.SIGINT)
    except Exception:
        sigint = None
    sys.argv = [name] + args
    sys.stdout, sys.stderr = out, err
    error = ""
    try:
        runpy.run_path(path, run_name="__main__")
    except SystemExit as e:
        if e.code not in (None, 0):
            error = "exited with status %s" % e.code
    except KeyboardInterrupt:
        error = "interrupted"
    except Exception as e:
        error = "%s: %s" % (type(e).__name__, e)
    finally:
        sys.argv, sys.stdout, sys.stderr = saved
        if sigint is not None:
            try:
                signal.signal(signal.SIGINT, sigint)
            except Exception:
                pass
    text = out.getvalue()
    if err.getvalue().strip():
        text = text + ("\n" if text and not text.endswith("\n") else "") + err.getvalue()
    return text, error


def run_command(cmdline):
    """(lines, status, seconds) for one command line. A '| grep', '| head',
    '| tail' or '| wc -l' after it is applied here, since crash only pipes
    to a shell for commands typed at its prompt."""
    start = time.time()
    stages = [s.strip() for s in cmdline.split(" | ")]
    base = stages[0]
    words = base.split()
    status = "ok"
    if not words:
        return [], "empty command", 0.0
    if is_pycrashext(words[0]):
        text, error = run_pycrashext(words[0], words[1:])
        if error:
            status = "error: " + error
    else:
        try:
            text = exec_crash_command(base)
        except Exception as e:
            # pykdump raises on empty output too: that is not a failure.
            text = str(e)
            if text.strip():
                status = "error: crash reported a failure"
    lines = evidplan.clean(text)
    for stage in stages[1:]:
        try:
            filtered = evidplan.pipe_filter(lines, stage)
        except Exception:
            filtered = None
        if filtered is None:
            status = ("error: '| %s' is not run here: only grep [-i -v -E], head -n N, "
                      "tail -n N and wc -l are, as the real command would" % stage)
            break
        lines = filtered
    return lines, status, time.time() - start


def read_case(task_dir):
    if not task_dir:
        return ""
    try:
        with open(os.path.join(task_dir, "caseno")) as f:
            return f.read().strip()
    except Exception:
        return ""


def default_path(task, case):
    name = "vmcore-%s-evidence.md" % (task or "unknown")
    if case:
        d = os.path.expanduser("~/gemini/%s" % case)
        try:
            os.makedirs(d, exist_ok=True)
            if os.access(d, os.W_OK):
                return os.path.join(d, name)
        except OSError:
            pass
    for d in (os.getcwd(), os.path.expanduser("~")):
        if os.access(d, os.W_OK):
            return os.path.join(d, name)
    return name


def extra_commands(o):
    cmds = []
    if o.extra:
        cmds.extend(c.strip() for c in o.extra.split(";"))
    if o.cmdfile:
        with open(o.cmdfile) as f:
            cmds.extend(l.strip() for l in f if l.strip() and not l.lstrip().startswith("#"))
    return [c for c in cmds if c]


def collect(steps, task, raw, blocks, failed, quiet):
    for step in steps:
        if not quiet:
            print("evidence: %s" % step.cmd)
            sys.stdout.flush()
        lines, status, secs = run_command(step.cmd)
        raw[step.cmd] = lines
        kept, skipped = evidplan.cap(lines, step.head, step.tail)
        blocks.append(evidplan.block(step, task, kept, skipped, status, secs))
        if status != "ok":
            failed.append("%s: %s" % (step.cmd, status))


def evidence():
    op = OptionParser(usage="evidence [-o FILE] [-x 'cmd; cmd'] [-f FILE] [-a] [--stdout] [-q]")
    op.add_option("-o", "--output", dest="output", default="", help="Write the evidence file here")
    op.add_option("-t", "--task", dest="task", default="", help="Task ID, when the DUMPFILE path does not hold it")
    op.add_option("-x", "--extra", dest="extra", default="",
                  help="More commands to run, separated by ';'")
    op.add_option("-f", "--file", dest="cmdfile", default="", help="More commands, one per line")
    op.add_option("-a", "--append", dest="append", default=0, action="store_true",
                  help="Only run the -x/-f commands, appended to the existing file")
    op.add_option("--stdout", dest="stdout", default=0, action="store_true",
                  help="Print the evidence instead of writing a file")
    op.add_option("-q", "--quiet", dest="quiet", default=0, action="store_true",
                  help="Do not print each command as it runs")
    (o, args) = op.parse_args()

    sys_lines, _, _ = run_command("sys")
    fields = evidplan.parse_sys("\n".join(sys_lines))
    task, task_dir = evidplan.task_from_dumpfile(fields.get("DUMPFILE", ""))
    task = o.task or task
    case = read_case(task_dir)
    path = o.output or ("" if o.stdout else default_path(task, case))
    extras = [evidplan.Step(c, "Follow-up: %s" % c, 80, 40) for c in extra_commands(o)]

    raw, blocks, failed = {}, [], []
    if o.append:
        if not extras:
            print("evidence: -a needs commands (-x or -f)")
            return
        collect(extras, task, raw, blocks, failed, o.quiet)
        text = "\n".join(l for b in blocks for l in b)
        if o.stdout:
            print(text)
            return
        with open(path, "a") as f:
            f.write("\n" + text)
        print("evidence: appended %d block(s) to %s" % (len(blocks), path))
        print("EVIDENCE file=%s task=%s case=%s appended=%d bytes=%d" % (
            path, task or "unknown", case or "unknown", len(blocks), os.path.getsize(path)))
        return

    collect(evidplan.base_steps(), task, raw, blocks, failed, o.quiet)
    cls = evidplan.classify(fields, raw.get("log", []))
    exc = evidplan.parse_exception("\n".join(raw.get("bt", [])))
    collect(evidplan.branch_steps(cls, exc, fields), task, raw, blocks, failed, o.quiet)
    if extras:
        collect(extras, task, raw, blocks, failed, o.quiet)

    meta = {"task": task, "case": case, "host": fields.get("NODENAME", ""),
            "kernel": fields.get("RELEASE", ""), "panic": fields.get("PANIC", "").strip('"'),
            "when": time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())}
    doc = evidplan.render(meta, cls, exc, blocks, failed)
    if o.stdout:
        print(doc)
        return
    with open(path, "w") as f:
        f.write(doc)
    size = os.path.getsize(path)
    print("evidence: %d command(s), %d failed; branches %s; %d bytes (about %dk tokens)" % (
        len(blocks), len(failed), ",".join(cls["branches"]), size, size // 4000))
    print("evidence: written to %s" % path)
    print(evidplan.summary_line(path, meta, cls, len(blocks), size))


if ( __name__ == '__main__'):
    evidence()
