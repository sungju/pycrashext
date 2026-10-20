"""
External command directories for regext.py: PYCRASHEXT_COMMAND_PATH.

Each directory PYCRASHEXT_COMMAND_PATH lists holds its own config.json, in
the same format as source/config.json, next to the command files it names.
regext.py registers those commands with the built-in ones, so commands kept
outside this repository show up in crash like any other.

crash looks a registered command up as <name>.py along PYKDUMPPATH, which
PyKdump reads once when the extension loads. A directory that is not on
PYKDUMPPATH would register commands crash cannot run, so it is skipped with
a warning instead.

This module deliberately imports nothing from pykdump, so its checks run
with the system python3 (extcmds_test.py).

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import json
import os

COMMAND_PATH_ENV = "PYCRASHEXT_COMMAND_PATH"


def split_path(path_value):
    """The real paths in a PATH-style value, in order, without empty entries."""
    paths = []
    for entry in (path_value or "").split(os.pathsep):
        entry = entry.strip()
        if entry:
            paths.append(os.path.realpath(os.path.expanduser(entry)))
    return paths


def read_commands(config_file):
    """The 'commands' list of one config.json; raises ValueError when malformed."""
    with open(config_file, "r") as f:
        data = json.load(f)
    commands = data.get("commands", []) if isinstance(data, dict) else None
    if not isinstance(commands, list):
        raise ValueError("'commands' is not a list")
    return commands


def external_commands(environ, builtin_names):
    """The command entries from every PYCRASHEXT_COMMAND_PATH directory.

    Returns (entries, warnings). An entry never replaces a built-in command
    or one from an earlier directory: which file crash runs for a name is
    decided by PYKDUMPPATH order, not by this list, so a clash is refused
    rather than left ambiguous.
    """
    entries, warnings = [], []
    taken = set(builtin_names)
    kdump_path = split_path(environ.get("PYKDUMPPATH", ""))
    seen = set()

    for cmd_dir in split_path(environ.get(COMMAND_PATH_ENV, "")):
        if cmd_dir in seen:
            continue
        seen.add(cmd_dir)
        if not os.path.isdir(cmd_dir):
            warnings.append("%s: '%s' is not a directory, skipped" % (COMMAND_PATH_ENV, cmd_dir))
            continue
        if cmd_dir not in kdump_path:
            warnings.append("%s: '%s' is not on PYKDUMPPATH, so crash cannot run "
                            "its commands; skipped" % (COMMAND_PATH_ENV, cmd_dir))
            continue

        config_file = os.path.join(cmd_dir, "config.json")
        try:
            commands = read_commands(config_file)
        except (OSError, ValueError) as e:
            warnings.append("%s: cannot read '%s': %s" % (COMMAND_PATH_ENV, config_file, e))
            continue

        for cmd in commands:
            if isinstance(cmd, dict) and cmd.get("enabled", True) is False:
                continue
            name =str(cmd.get("command", "")).strip() if isinstance(cmd, dict) else ""
            if name in taken:
                warnings.append("%s: '%s' from '%s' is already registered, skipped"
                                % (COMMAND_PATH_ENV, name, cmd_dir))
                continue
            if name and not os.path.isfile(os.path.join(cmd_dir, name + ".py")):
                warnings.append("%s: '%s' has no %s.py in '%s', skipped"
                                % (COMMAND_PATH_ENV, name, name, cmd_dir))
                continue
            if name:
                taken.add(name)
            entries.append(cmd)

    return entries, warnings
