"""
 Written by Daniel Sungju Kwon
"""

from crash import register_epython_prog as rprog

from pykdump.API import *

import os
import sys
import json
import traceback

import crashcolor

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


def load_json_config():
    try:
        with open("config.json", "r") as f:
            data = json.load(f)
        commands = data['commands']
        for cmd in commands:
            rprog(cmd['command'], cmd['desc'],
                  cmd['options'], cmd['help'])
    except Exception as e:
        crashcolor.set_color(crashcolor.RED)
        traceback.print_exc()
        crashcolor.set_color(crashcolor.RESET)


load_json_config()

