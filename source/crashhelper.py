#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Sungju Kwon <sungju.kwon@gmail.com>
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
import time
import shlex
import tempfile


def run_command_with_file(func, command, file_content):
    """exec_gdb_command() is failing to capture the output
    if the command is with '!' which is important to execute
    shell commands. Below will capture it properly."""
    temp_output_name = ""
    temp_error_name = ""
    temp_input_name = ""
    lines = ""

    def _safe_remove(path_name):
        try:
            if path_name != "" and os.path.exists(path_name):
                os.remove(path_name)
        except:
            pass

    try:
        tmp_output = tempfile.NamedTemporaryFile(delete=False, prefix="pycrashext-output-", suffix=".txt")
        tmp_error = tempfile.NamedTemporaryFile(delete=False, prefix="pycrashext-error-", suffix=".txt")
        temp_output_name = tmp_output.name
        temp_error_name = tmp_error.name
        tmp_output.close()
        tmp_error.close()

        command = command + " > " + shlex.quote(temp_output_name) + \
                " 2> " + shlex.quote(temp_error_name)
        if file_content != "":
            with tempfile.NamedTemporaryFile(delete=False, mode='w',
                                            prefix="pycrashext-input-", suffix=".txt") as fp:
                fp.write(file_content)
                temp_input_name = fp.name
            command = command + " < " + shlex.quote(temp_input_name)

        func(command)
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
    except Exception as e:
        lines = str(e)
    finally:
        for tmp_name in [temp_output_name, temp_error_name, temp_input_name]:
            _safe_remove(tmp_name)

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


def get_sizeof_struct(struct_name):
    result_size = 0
    try:
        output_lines = run_crash_command(struct_name).splitlines()
        if len(output_lines) == 0:
            return result_size
        result_str = output_lines[-1]
        size_str = result_str.split()[1]
        if size_str.startswith("0x"):
            result_size = int(size_str, 16)
        else:
            result_size = int(size_str)
    except Exception as e:
        print(e)
        pass

    return result_size
