"""
Written by Daniel Sungju Kwon

This is running extra rules to detect known issues.
"""
import os
import sys
import re
import importlib

modules = []
sysinfo = {}

def get_system_info():
    global sysinfo

    resultlines = exec_crash_command("sys").splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = words[1].strip()


def load_rules():
    global modules
    global sysinfo

    pysearchre = re.compile('.py$', re.IGNORECASE)
    try:
        cmd_path_list = os.environ["PYKDUMPPATH"]
        path_list = cmd_path_list.split(':')
        source_path = ""
        for path in path_list:
            if os.path.exists(path + "/rules"):
                source_path = path + "/rules"
                break
    except:
        print ("Couldn't find ./rules directory")
        return

    rulefiles = filter(pysearchre.search, os.listdir(source_path))
    form_module = lambda fp: '.' + os.path.splitext(fp)[0]
    rules = map(form_module, rulefiles)
    importlib.import_module('rules')
    for rule in rules:
        if not rule.startswith('.__'):
            new_module = importlib.import_module(rule, package="rules")
            if new_module.add_rule(sysinfo) == True:
               modules.append(new_module)
    return modules


def run_rules():
    global modules
    global sysinfo

    for module in modules:
        if module.run_rule(sysinfo) == False:
            break # Let's not continue if it returns False

def autocheck():
    get_system_info()
    load_rules()
    run_rules()


if ( __name__ == '__main__'):
        autocheck()
