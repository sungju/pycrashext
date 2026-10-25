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
import re
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


def check_trigger_only_as_its_own_option():
    op = _parser()
    # '-hh' as the value of -n is that value, not a request for examples.
    assert _run(op, {}, ["cmd.py", "-n", "-hh"]) == ("", None)
    assert _run(op, {}, ["cmd.py", "--", "-hh"]) == ("", None)
    assert _run(op, {}, ["cmd.py", "-n", "foo", "-hh"])[1] == 0
    assert _run(op, {}, ["cmd.py", "-s", "-hh"])[1] == 0
    assert _run(op, {}, ["cmd.py", "-n", "-hh", "-hh"])[1] == 0


def check_default_none_as_optparse_prints_it():
    op = _parser()
    op.add_option("-x", dest="x", help="X (default: %default)")
    text, _ = _run(op, {}, ["cmd.py", "-hh"])
    assert "      X (default: none)\n" in text, text
    assert "(default: none)" in op.format_help()


def _option_strings(call):
    return [a.value for a in call.args
            if isinstance(a, ast.Constant) and isinstance(a.value, str) and
            a.value.startswith("-")]


# add_option actions that take no value; optparse's default action, 'store',
# takes one.
NO_VALUE_ACTIONS = ("store_true", "store_false", "store_const", "append_const",
                    "count", "help", "version")


def _takes_value(call):
    for kw in call.keywords:
        if kw.arg == "action" and isinstance(kw.value, ast.Constant):
            return kw.value.value not in NO_VALUE_ACTIONS
    return True


def _default_example(cmd, opts):
    """optexamples.default_example() for a flag, from the option strings."""
    short = [s for s in opts if len(s) == 2 and s[1] != "-"]
    return "%s %s" % (cmd, (short or opts)[0])


def _command_files():
    for path in sorted(glob.glob(os.path.join(HERE, "*.py"))):
        if path.endswith("_test.py") or os.path.basename(path) == "optexamples.py":
            continue
        with open(path) as f:
            src = f.read()
        if "add_option(" in src:
            yield path, ast.parse(src, path)


def _is_call(node, attr):
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
        and node.func.attr == attr


def _handle_order(tree):
    """Functions that call parse_args() without optexamples.handle() first."""
    bad = []
    for func in ast.walk(tree):
        if not isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        parses = [n.lineno for n in ast.walk(func) if _is_call(n, "parse_args")]
        if not parses:
            continue
        handles = [n.lineno for n in ast.walk(func) if _is_call(n, "handle") and
                   isinstance(n.func.value, ast.Name) and
                   n.func.value.id == "optexamples"]
        if not handles or min(handles) > min(parses):
            bad.append(func.name)
    return bad


def check_every_option_has_examples():
    """Each command calls optexamples.handle() before parse_args(), and its
    OPTION_EXAMPLES has an entry for every option that takes a value. A flag
    may go without one: '-hh' then prints '<cmd> <flag>', so an entry that
    says only that is reported as redundant."""
    missing = []
    for path, tree in _command_files():
        name = os.path.basename(path)
        cmd = name[:-3]
        examples = None
        options = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and any(
                    isinstance(t, ast.Name) and t.id == "OPTION_EXAMPLES"
                    for t in node.targets):
                try:
                    examples = ast.literal_eval(node.value)
                except ValueError:
                    missing.append("%s:%d: OPTION_EXAMPLES is not a literal" %
                                   (name, node.lineno))
                    examples = {}
            elif _is_call(node, "add_option"):
                opts = _option_strings(node)
                if opts:
                    options.append((opts, _takes_value(node)))
        for func in _handle_order(tree):
            missing.append("%s: %s() calls parse_args() without "
                           "optexamples.handle() before it" % (name, func))
        if examples is None:
            missing.append("%s: no OPTION_EXAMPLES" % name)
            continue
        known = set(s for opts, _ in options for s in opts)
        for key, value in examples.items():
            if key not in known:
                missing.append("%s: OPTION_EXAMPLES has unknown option %s" % (name, key))
            lines = [value] if isinstance(value, str) else value
            if not lines or not all(isinstance(l, str) and l for l in lines):
                missing.append("%s: empty examples for %s" % (name, key))
        for opts, takes_value in options:
            given = [examples[s] for s in opts if s in examples]
            if takes_value and not given:
                missing.append("%s: no examples for %s" % (name, "/".join(opts)))
            elif not takes_value and given:
                lines = [given[0]] if isinstance(given[0], str) else given[0]
                if list(lines) == [_default_example(cmd, opts)]:
                    missing.append("%s: example for %s is the generated one; "
                                   "drop it" % (name, "/".join(opts)))
    assert not missing, "\n".join(missing)


def _option_names(text):
    """'--max-count=<n>, -n' -> ['--max-count', '-n']; '-S<string>' -> ['-S']."""
    return re.findall(r"(?<![\w-])-{1,2}[A-Za-z][A-Za-z-]*", text)


def _help_options(stmts):
    """The option names in the '  -x ...' lines printed by `stmts`."""
    names = set()
    for node in stmts:
        for n in ast.walk(node):
            if isinstance(n, ast.Constant) and isinstance(n.value, str) and \
                    re.match(r"^  -", n.value):
                names.update(_option_names(re.split(r"\s{2,}", n.value.strip())[0]))
    return names


def check_git_examples_match_help():
    """git keeps its own OPTION_EXAMPLES; each subcommand's table covers the
    options its --help lists, and names no option git's help doesn't."""
    path = os.path.join(HERE, "git.py")
    with open(path) as f:
        tree = ast.parse(f.read(), path)
    funcs = {n.name: n for n in tree.body if isinstance(n, ast.FunctionDef)}
    table = None
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "OPTION_EXAMPLES"
                for t in node.targets):
            table = ast.literal_eval(node.value)
    common = _help_options(funcs["print_help"].body)
    sub_help = {}
    branch = funcs["print_help_for_subcommand"].body[0]
    while isinstance(branch, ast.If):
        sub_help[branch.test.comparators[0].value] = _help_options(branch.body)
        branch = branch.orelse[0] if branch.orelse else None
    assert set(table) == set(sub_help), (sorted(table), sorted(sub_help))
    problems = []
    for sub, rows in table.items():
        names = set()
        for label, help_str, examples in rows:
            names.update(_option_names(label))
            if not help_str or not examples or \
                    not all(e.startswith("git %s " % sub) for e in examples):
                problems.append("git %s %s: bad help or examples" % (sub, label))
        for opt in sorted(sub_help[sub] - names - {"-hh"}):
            problems.append("git %s: no examples for %s" % (sub, opt))
        for opt in sorted(names - sub_help[sub] - common):
            problems.append("git %s: %s is in no help text" % (sub, opt))
    assert not problems, "\n".join(problems)


if (__name__ == '__main__'):
    checks = [v for k, v in sorted(globals().items()) if k.startswith('check_')]
    for check in checks:
        check()
        print("ok  %s" % check.__name__)
    print("\n%d checks passed" % len(checks))
