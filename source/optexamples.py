"""
'-hh' for pycrashext commands: each option with its help and examples.

'<command> -h' is optparse's own help. '<command> -hh' goes one step
further and shows, for every option, the help line and one or more
example command lines. A command keeps its examples in a dict keyed by an
option string (short or long, as given to add_option) and calls

    optexamples.handle(op, OPTION_EXAMPLES)

just before op.parse_args(). handle() returns at once unless '-hh' is on
the command line; then it prints the examples and exits, as '-h' does.
It also adds a line to the '-h' text pointing at '-hh'.

An option missing from the dict still gets a line built from its own
name, so a new option shows up in '-hh' before anyone writes an example
for it (optexamples_test.py reports those).

This module deliberately imports nothing from pykdump, so its checks run
with the system python3 (optexamples_test.py).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import sys
import textwrap
from optparse import NO_DEFAULT, SUPPRESS_HELP

TRIGGER = "-hh"
HINT = "Run '%s -hh' for examples of each option."


def command_name(argv0):
    """'.../edis.py' -> 'edis'."""
    name = os.path.basename(argv0 or "")
    return name[:-3] if name.endswith(".py") else name


def add_hint(op, cmd):
    """Point '-h' at '-hh', once."""
    hint = HINT % cmd
    if op.epilog is None:
        op.epilog = hint
    elif hint not in op.epilog:
        op.epilog = op.epilog.rstrip() + "\n\n" + hint


def visible_options(op):
    """The options '-h' shows, '-h' itself left out."""
    opts = list(op.option_list)
    for group in op.option_groups:
        opts.extend(group.option_list)
    return [o for o in opts
            if o.help != SUPPRESS_HELP and o.dest is not None and
            o.action != "help"]


def option_label(opt):
    """'-s, --softirq' or '-n NAME, --name=NAME', as '-h' prints it."""
    mv = _metavar(opt) if opt.takes_value() else None
    names = [s + (" " + mv if mv else "") for s in opt._short_opts]
    names += [l + ("=" + mv if mv else "") for l in opt._long_opts]
    return ", ".join(names)


def _metavar(opt):
    return opt.metavar or (opt.dest or "value").upper()


def default_example(cmd, opt):
    """'bh -s', or 'cginfo -s <SUBSYS>' for an option that takes a value."""
    name = (opt._short_opts or opt._long_opts)[0]
    if opt.takes_value():
        return "%s %s <%s>" % (cmd, name, _metavar(opt))
    return "%s %s" % (cmd, name)


def examples_for(opt, examples):
    """The examples given for `opt` under any of its option strings."""
    for s in opt._short_opts + opt._long_opts:
        if s in examples:
            ex = examples[s]
            return [ex] if isinstance(ex, str) else list(ex)
    return []


def default_text(op, opt):
    """What optparse's own '-h' puts in place of %default."""
    value = op.defaults.get(opt.dest)
    if value is NO_DEFAULT or value is None:
        return "none"
    return str(value)


def wants_examples(op, args):
    """
    True when '-hh' is on the command line as an option of its own, not as
    the value of an option that takes one ('edis -j -hh') or after '--'.
    """
    prev = None
    for arg in args:
        if arg == "--":
            return False
        if arg == TRIGGER:
            opt = op._short_opt.get(prev) or op._long_opt.get(prev)
            if opt is None or not opt.takes_value():
                return True
        prev = arg
    return False


def format_examples(op, examples, cmd):
    """The '-hh' text."""
    out = []
    usage = op.get_usage().strip()
    if usage:
        out.append(usage)
        out.append("")
    out.append("Examples for each option:")
    for opt in visible_options(op):
        out.append("")
        out.append("  " + option_label(opt))
        help_text = op.expand_prog_name(opt.help or "")
        if "%default" in help_text:
            help_text = help_text.replace("%default", default_text(op, opt))
        for line in textwrap.wrap(" ".join(help_text.split()), 70):
            out.append("      " + line)
        for ex in examples_for(opt, examples) or [default_example(cmd, opt)]:
            out.append("      crash> " + ex)
    return "\n".join(out) + "\n"


def handle(op, examples, argv=None, out=None):
    """
    Call just before op.parse_args(). With '-hh' on the command line, print
    every option's examples and exit; otherwise only add the '-hh' hint to
    the '-h' text and return.
    """
    argv = sys.argv if argv is None else argv
    cmd = command_name(argv[0] if argv else "")
    add_hint(op, cmd)
    if not wants_examples(op, argv[1:]):
        return
    (out or sys.stdout).write(format_examples(op, examples, cmd))
    sys.exit(0)
