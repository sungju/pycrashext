"""
Registers the pycrashext commands in crash from config.json.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from crash import register_epython_prog as rprog

from pykdump.API import *

import os
import sys
import io
import json
import re
import runpy
import traceback
import contextlib

import crashcolor
import extcmds
import helptext

try:
    if "PYTHON_LIB" in os.environ:
        additional_lib = os.environ["PYTHON_LIB"]
        python_path_list = additional_lib.split(':')
        for python_path in python_path_list:
            python_lib = python_path
            if python_lib not in sys.path:
                sys.path.insert(0, python_lib)
except Exception as e:
    crashcolor.set_color(crashcolor.RED)
    print('Error: ' + str(e))
    crashcolor.set_color(crashcolor.RESET)

# Add the source directory to Python path so command modules can be imported
source_dir = os.path.dirname(os.path.abspath(__file__))
if source_dir not in sys.path:
    sys.path.insert(0, source_dir)


def validate_command_entry(cmd_entry):
    """
    Validate one command entry from config.
    Returns a normalized mapping if valid, otherwise None.
    """
    if not isinstance(cmd_entry, dict):
        return None

    if cmd_entry.get("enabled", True) is False:
        return None

    required_fields = ["command", "desc", "options", "help"]
    for field in required_fields:
        if field not in cmd_entry:
            return None

    command_name = str(cmd_entry['command']).strip()
    if command_name == "":
        return None

    # Keep command names simple and safe for crash command registration
    if not re.match(r"^[a-zA-Z0-9_.-]+$", command_name):
        return None

    return {
        "command": command_name,
        "desc": str(cmd_entry['desc']),
        "options": str(cmd_entry['options']),
        "help": str(cmd_entry['help']),
    }


def command_help(script):
    """
    What '<command> -h' prints, so 'help <command>' and 'man <command>' can
    show the same. The script runs here as crash would run it, with '-h' as
    its only argument; optparse prints the help and exits. None if it fails.
    """
    saved_argv = sys.argv
    out = io.StringIO()
    sys.argv = [script, "-h"]
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                runpy.run_path(script, run_name="__main__")
            except SystemExit:
                pass
    except Exception:
        return None
    finally:
        sys.argv = saved_argv
    return out.getvalue()


def load_json_config():
    try:
        config_file = os.path.dirname(sys.argv[0]) + "/config.json"
        with open(config_file, "r") as f:
            data = json.load(f)
        commands = data.get('commands', [])
        if not isinstance(commands, list):
            crashcolor.set_color(crashcolor.RED)
            print("Invalid config: 'commands' is not a list")
            crashcolor.set_color(crashcolor.RESET)
            return

        registered = {}
        for cmd in commands:
            normalized = validate_command_entry(cmd)
            if normalized is None:
                continue

            cmd_name = normalized['command']
            if cmd_name in registered:
                crashcolor.set_color(crashcolor.YELLOW)
                print("Duplicate command '%s' in config; overriding previous entry" % cmd_name)
                crashcolor.set_color(crashcolor.RESET)
            registered[cmd_name] = normalized

        ext_entries, ext_warnings = extcmds.external_commands(os.environ,
                                                              registered.keys())
        crashcolor.set_color(crashcolor.YELLOW)
        for warning in ext_warnings:
            print(warning)
        crashcolor.set_color(crashcolor.RESET)
        for cmd in ext_entries:
            normalized = validate_command_entry(cmd)
            if normalized is not None:
                registered[normalized['command']] = normalized

        script_dirs = extcmds.split_path(os.environ.get("PYKDUMPPATH", "")) + \
                      [source_dir]
        cache_path = helptext.cache_file(os.environ)
        cache = helptext.load_cache(cache_path)
        cache_changed = False
        for cmd_name, cmd_info in registered.items():
            options, help_str = cmd_info['options'], cmd_info['help']
            script = helptext.find_script(cmd_name, script_dirs)
            if script is not None:
                text, changed = helptext.cached_help(cache, script, command_help)
                cache_changed = cache_changed or changed
                options, help_str = helptext.crash_help(cmd_info, text)
            rprog(cmd_info['command'], cmd_info['desc'], options, help_str)
        if cache_changed:
            helptext.save_cache(cache_path, cache)
    except Exception as e:
        crashcolor.set_color(crashcolor.RED)
        traceback.print_exc()
        crashcolor.set_color(crashcolor.RESET)


load_json_config()
