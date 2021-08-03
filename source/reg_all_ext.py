"""
 Written by Daniel Sungju Kwon
"""

from crash import register_epython_prog as rprog
from pykdump.API import *

import os
import sys
import re

new_path = ""

def add_path(path):
    global new_path

    if "PYKDUMPPATH" in os.environ:
        cur_path = os.environ["PYKDUMPPATH"]
        if path not in cur_path:
            new_path = path + ":" + new_path


def reg_command(command, fpath):
    for ver in "", "v1", "v2", "v3":
        result = exec_crash_command("alias %s%s \"epython %s\"" % (command, ver, fpath))
        if not result.startswith("alias: cannot alias existing"):
            break


def reg_command_dir(path):
    command_files = os.listdir(path)
    file_cnt = 0
    for command in command_files:
        if command.startswith("__") or command.startswith("."):
            continue
        fpath = os.path.join(path, command)
        if os.path.isdir(fpath):
            reg_command_dir(fpath)
        else:
            command = os.path.splitext(command)[0]
            reg_command(command, fpath)
            file_cnt = file_cnt + 1

    if file_cnt > 0:
        add_path(path)


def regsiter_all_commands():
    op = OptionParser()
    (o, args) = op.parse_args()
    reg_command_dir(args[0])
    exec_crash_command("alias eextend \"alias | grep runtime | awk '{ print $2 }'\"")


if ( __name__ == '__main__' ):
    regsiter_all_commands()
