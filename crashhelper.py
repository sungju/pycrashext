"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *
from os.path import expanduser
import os
import sys


def run_gdb_command(command):
    """exec_gdb_command() is failing to capture the output
    if the command is with '!' which is important to execute
    shell commands. Below will capture it properly."""
    temp_name = expanduser("~") + "/" + time.strftime("%Y%m%d-%H%M%S-pycrashext-tmp")
    command = command + " > " + temp_name
    exec_gdb_command(command)
    lines = ""
    if os.path.exists(temp_name):
        with open(temp_name, 'r') as f:
            try:
                lines = "".join(f.readlines())
            except:
                lines = "Failed to read " + temp_name

    os.remove(temp_name)
    return lines
