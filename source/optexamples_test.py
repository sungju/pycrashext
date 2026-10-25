"""
Checks for optexamples.py, the '-hh' examples, and that every command
gives examples for each of its options.

Run directly: python3 source/optexamples_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import ast
import glob
import io
import os
from optparse import OptionParser

import optexamples

HERE = os.path.dirname(os.path.abspath(__file__))


def _parser():
    op = OptionParser(usage="cmd [options]")
    op.add_option("-s", "--softirq", dest="softirq", action="store_true",
                  help="Show softirq list")
    op.add_option("-n", "--name", dest="name", default="all",
                  help="Filter by name (default: %default)")
    return op


def _run(op, examples, argv):
    out = io.StringIO()
    try:
        optexamples.handle(op, examples, argv=argv, out=out)
    except SystemExit as e:
        return out.getvalue(), e.code
    return out.getvalue(), None


def check_no_trigger_returns():
    op = _parser()
    text, code = _run(op, {}, ["/x/cmd.py", "-s"])
    assert text == "" and code is None
    assert op.epilog == "Run 'cmd -hh' for examples of each option."
    # Called twice, the hint is still there once.
    optexamples.add_hint(op, "cmd")
    assert op.epilog.count("-hh") == 1


def check_hint_after_epilog():
    op = _parser()
    op.epilog = "More text."
    optexamples.add_hint(op, "cmd")
    assert op.epilog == "More text.\n\nRun 'cmd -hh' for examples of each option."


def check_examples_output():
    examples = {"--softirq": ["cmd -s", "cmd -s -n foo"]}
    text, code = _run(_parser(), examples, ["cmd.py", "-hh"])
    assert code == 0
    assert text.startswith("Usage: cmd [options]\n\nExamples for each option:\n"), text
    assert "  -s, --softirq\n      Show softirq list\n" \
           "      crash> cmd -s\n      crash> cmd -s -n foo\n" in text, text
    # No example given: one built from the option, with %default filled in.
    assert "  -n NAME, --name=NAME\n      Filter by name (default: all)\n" \
           "      crash> cmd -n <NAME>\n" in text, text
    assert "--help" not in text


def check_single_string_example():
    text, _ = _run(_parser(), {"-n": "cmd -n bar"}, ["cmd.py", "-hh"])
    assert "      crash> cmd -n bar\n" in text


def _option_strings(call):
    return [a.value for a in call.args
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and
            a.value.startswith("-")]


def _command_files():
    for path in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        if path.endswith("_test.py") or os.path.basename(path) == "optexamples.py":
            continue
        with open(path) as f:
            src = f.read()
        if "add_option(" in src:
            yield path, ast.parse(src, path)


def check_every_option_has_examples():
    """Each command calls optexamples.handle() and its OPTION_EXAMPLES has
    an entry for every option it adds."""
    missing = []
    for path, tree in _command_files():
        name = os.path.basename(path)
        examples = None
        handled = False
        options = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "OPTION_EXAMPLES"
                    for t in node.targets):
                examples = ast.literal_eval(node.value)
            elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr == "add_option":
                    options.append(_option_strings(node))
                elif node.func.attr == "handle" and \
                        isinstance(node.func.value, ast.Name) and \
                        node.func.value.id == "optexamples":
                    handled = True
        if not handled:
            missing.append("%s: no optexamples.handle() call" % name)
        if examples is None:
            missing.append("%s: no OPTION_EXAMPLES" % name)
            continue
        known = set(s for opts in options for s in opts)
        for key, value in examples.items():
            if key not in known:
                missing.append("%s: OPTION_EXAMPLES has unknown option %s" % (name, key))
            lines = [value] if isinstance(value, str) else value
            if not lines or not all(isinstance(l, str) and l for l in lines):
                missing.append("%s: empty examples for %s" % (name, key))
        for opts in options:
            if opts and not any(s in examples for s in opts):
                missing.append("%s: no examples for %s" % (name, "/".join(opts)))
    assert not missing, "\n".join(missing)


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
