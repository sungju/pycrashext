#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Daniel Sungju Kwon <dkwon@redhat.com>
#
# This is providing helper functions to run shell commands
#
#
# Contributors:
# --------------------------------------------------------------------
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
from pykdump.API import *
from os.path import expanduser
import os
import sys


def run_command_with_file(func, command, file_content):
    """exec_gdb_command() is failing to capture the output
    if the command is with '!' which is important to execute
    shell commands. Below will capture it properly."""
    try:
        temp_output_name = expanduser("~") + "/" + time.strftime("%Y%m%d-%H%M%S-pycrashext-output-tmp")
        temp_error_name = expanduser("~") + "/" + time.strftime("%Y%m%d-%H%M%S-pycrashext-error-tmp")
        temp_input_name = expanduser("~") + "/" + time.strftime("%Y%m%d-%H%M%S-pycrashext-input-tmp")
        command = command + " > " + temp_output_name + " 2> " + temp_error_name
        if file_content != "":
            with open(temp_input_name, 'w') as f:
                f.write(file_content)
            command = command + " < " + temp_input_name

        func(command)
        lines = ""
        if os.path.exists(temp_output_name):
            with open(temp_output_name, 'r') as f:
                try:
                    lines = lines + "".join(f.readlines())
                except:
                    lines = "Failed to read " + temp_output_name

        if os.path.exists(temp_error_name):
            with open(temp_error_name, 'r') as f:
                try:
                    lines = lines + "".join(f.readlines())
                except:
                    lines = "Failed to read " + temp_error_name

        try:
            os.remove(temp_output_name)
            os.remove(temp_error_name)
            os.remove(temp_input_name)
        except:
            pass
    except Exception as e:
        lines = str(e)

    return lines


def run_command(func, command):
    return run_command_with_file(func, command, "")


def run_gdb_command(command):
    return run_command(exec_gdb_command, command)


def run_crash_command(command):
    return run_command(exec_crash_command, command)


def run_gdb_command_with_file(command, file_content):
    return run_command_with_file(exec_gdb_command, command, file_content)


def run_crash_command_with_file(command, file_content):
    return run_command_with_file(exec_crash_command, command, file_content)
