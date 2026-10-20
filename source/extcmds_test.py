"""
Checks for PYCRASHEXT_COMMAND_PATH, the external command directories
regext.py registers.

Run directly: python3 source/extcmds_test.py

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import json
import os
import shutil
import tempfile

from extcmds import external_commands


def entry(name, **extra):
    cmd = {"command": name, "desc": name + " desc", "options": "-h", "help": name + " help"}
    cmd.update(extra)
    return cmd


def make_dir(root, name, commands, files=None):
    """A command directory with a config.json and the named .py files."""
    path = os.path.join(root, name)
    os.makedirs(path)
    with open(os.path.join(path, "config.json"), "w") as f:
        json.dump({"commands": commands}, f)
    for stem in (files if files is not None else [c["command"] for c in commands]):
        open(os.path.join(path, stem + ".py"), "w").close()
    return os.path.realpath(path)


def env(cmd_dirs, kdump_dirs):
    return {"PYCRASHEXT_COMMAND_PATH": os.pathsep.join(cmd_dirs),
            "PYKDUMPPATH": os.pathsep.join(kdump_dirs)}


def names(entries):
    return [e["command"] for e in entries]


def check_unset_is_a_no_op(root):
    assert external_commands({}, ["bt"]) == ([], [])


def check_registers_commands_on_pykdumppath(root):
    d = make_dir(root, "site", [entry("kcs"), entry("jirafind")])
    entries, warnings = external_commands(env([d], ["/x", d]), ["devinfo"])
    assert names(entries) == ["kcs", "jirafind"], entries
    assert warnings == [], warnings


def check_dir_not_on_pykdumppath_is_skipped(root):
    d = make_dir(root, "site", [entry("kcs")])
    entries, warnings = external_commands(env([d], ["/x"]), [])
    assert entries == []
    assert len(warnings) == 1 and "not on PYKDUMPPATH" in warnings[0], warnings


def check_builtin_name_is_not_replaced(root):
    d = make_dir(root, "site", [entry("devinfo"), entry("kcs")])
    entries, warnings = external_commands(env([d], [d]), ["devinfo"])
    assert names(entries) == ["kcs"], entries
    assert "'devinfo'" in warnings[0] and "already registered" in warnings[0], warnings


def check_first_directory_wins(root):
    a = make_dir(root, "a", [entry("kcs", desc="from a")])
    b = make_dir(root, "b", [entry("kcs", desc="from b")])
    entries, warnings = external_commands(env([a, b], [a, b]), [])
    assert [e["desc"] for e in entries] == ["from a"], entries
    assert len(warnings) == 1, warnings


def check_missing_command_file_is_skipped(root):
    d = make_dir(root, "site", [entry("kcs"), entry("ghost")], files=["kcs"])
    entries, warnings = external_commands(env([d], [d]), [])
    assert names(entries) == ["kcs"], entries
    assert "ghost.py" in warnings[0], warnings


def check_disabled_entry_is_ignored(root):
    d = make_dir(root, "site", [entry("kcs", enabled=False)], files=[])
    assert external_commands(env([d], [d]), []) == ([], [])


def check_bad_config_and_missing_dir_warn(root):
    d = os.path.realpath(os.path.join(root, "broken"))
    os.makedirs(d)
    with open(os.path.join(d, "config.json"), "w") as f:
        f.write('{"commands": {"not": "a list"}}')
    gone = os.path.join(root, "gone")
    entries, warnings = external_commands(env([d, gone], [d, gone]), [])
    assert entries == []
    assert len(warnings) == 2, warnings
    assert "cannot read" in warnings[0] and "not a directory" in warnings[1], warnings


def check_paths_compare_by_real_path(root):
    d = make_dir(root, "site", [entry("kcs")])
    link = os.path.join(root, "link")
    os.symlink(d, link)
    entries, warnings = external_commands(env([link + os.sep], [d]), [])
    assert names(entries) == ["kcs"] and warnings == [], (entries, warnings)


def main():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("check_") and callable(fn):
            root = tempfile.mkdtemp()
            try:
                fn(root)
            finally:
                shutil.rmtree(root)
            n += 1
    print("extcmds: %d checks passed" % n)


if __name__ == "__main__":
    main()
