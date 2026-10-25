"""
Checks for helptext.py, the '-h' text regext.py registers for 'help' and
'man'.

Run directly: python3 source/helptext_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import shutil
import tempfile

import helptext

EDIS_H = """Usage: edis.py [options]

Options:
  -h, --help            show this help message and exit
  -r, --reverse         displays all instructions from the start of the
                        routine up to and including the designated address.
"""

GIT_H = """Error: Invalid subcommand '-h'
Usage: git <log|show|find> [options]
Try 'git log --help'
"""

CONFIG = {"command": "edis", "desc": "Enhanced disasm",
          "options": "-h   - list available options",
          "help": "enhanced disasm command related information"}


def check_split_help():
    usage, body = helptext.split_help(EDIS_H)
    assert usage == "edis.py [options]", usage
    assert body.startswith("Options:\n  -h, --help"), body
    assert body.endswith("designated address."), body

    # Lines before the usage line (an error) are dropped.
    usage, body = helptext.split_help(GIT_H)
    assert usage == "git <log|show|find> [options]" and body == "Try 'git log --help'"

    # A usage that wraps onto indented lines is one line.
    usage, body = helptext.split_help("usage: kvercmp [-k <kernel>]\n"
                                      "               <fixed kernel>...\n\nMore\n")
    assert usage == "kvercmp [-k <kernel>] <fixed kernel>..." and body == "More"

    assert helptext.split_help("no help here\n") == (None, "no help here")


def check_synopsis():
    assert helptext.synopsis("edis.py [options]") == "[options]"
    assert helptext.synopsis("pdata [-a|-n] <type> <address>") == "[-a|-n] <type> <address>"
    assert helptext.synopsis("sysinfo") == ""


def check_crash_help():
    options, help_str = helptext.crash_help(CONFIG, EDIS_H)
    assert options == "[options]"
    assert help_str.startswith("enhanced disasm command related information\n\nOptions:")

    # Only the first paragraph of a long config help is kept: the rest
    # repeats what '-h' prints.
    cfg = dict(CONFIG, help="Follows members.\n\n pdata <type> <address>\n -a  all")
    assert helptext.crash_help(cfg, EDIS_H)[1].startswith("Follows members.\n\nOptions:")

    # No usage in the output (the script failed or prints none): keep
    # config.json's strings.
    assert helptext.crash_help(CONFIG, None) == (CONFIG["options"], CONFIG["help"])
    assert helptext.crash_help(CONFIG, "Traceback ...") == (CONFIG["options"], CONFIG["help"])


def check_find_script_and_cache():
    root = tempfile.mkdtemp()
    try:
        a = os.path.join(root, "a")
        b = os.path.join(root, "b")
        os.makedirs(a)
        os.makedirs(b)
        for d in (a, b):
            with open(os.path.join(d, "cmd.py"), "w") as f:
                f.write("# %s\n" % d)
        script = helptext.find_script("cmd", [os.path.join(root, "none"), a, b])
        assert script == os.path.realpath(os.path.join(a, "cmd.py"))
        assert helptext.find_script("nosuch", [a, b]) is None

        calls = []

        def compute(path):
            calls.append(path)
            return "Usage: cmd [options]\n"

        cache = {}
        assert helptext.cached_help(cache, script, compute) == ("Usage: cmd [options]\n", True)
        assert helptext.cached_help(cache, script, compute) == ("Usage: cmd [options]\n", False)
        assert len(calls) == 1

        # Saved and loaded again, the entry still matches the file.
        path = helptext.cache_file({"XDG_CACHE_HOME": os.path.join(root, "cache")})
        assert path == os.path.join(root, "cache", "pycrashext", "help.json")
        assert helptext.save_cache(path, cache)
        loaded = helptext.load_cache(path)
        assert helptext.cached_help(loaded, script, compute)[1] is False
        assert len(calls) == 1

        # A changed script is run again.
        with open(script, "a") as f:
            f.write("# changed\n")
        assert helptext.cached_help(loaded, script, compute)[1] is True
        assert len(calls) == 2

        # So is one whose dependency (optexamples.py) changed.
        dep = os.path.join(a, "optexamples.py")
        with open(dep, "w") as f:
            f.write("# v1\n")
        assert helptext.cached_help(loaded, script, compute, [dep])[1] is True
        assert helptext.cached_help(loaded, script, compute, [dep])[1] is False
        with open(dep, "a") as f:
            f.write("# v2\n")
        assert helptext.cached_help(loaded, script, compute, [dep])[1] is True
        assert len(calls) == 4

        # A failed run is not cached.
        assert helptext.cached_help({}, script, lambda p: None) == (None, False)

        # A missing, broken or old-version cache reads as empty.
        assert helptext.load_cache(os.path.join(root, "missing.json")) == {}
        with open(os.path.join(root, "bad.json"), "w") as f:
            f.write("{not json")
        assert helptext.load_cache(os.path.join(root, "bad.json")) == {}
        with open(os.path.join(root, "old.json"), "w") as f:
            f.write('{"version": 0, "scripts": {}}')
        assert helptext.load_cache(os.path.join(root, "old.json")) == {}
    finally:
        shutil.rmtree(root)


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
