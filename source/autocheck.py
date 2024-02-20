"""
Written by Daniel Sungju Kwon

This is running extra rules to detect known issues.
"""
from __future__ import print_function
from __future__ import division

import os
import sys
import re
import importlib

import crashcolor

modules = []
sysinfo = {}

def get_system_info():
    global sysinfo

    resultlines = exec_crash_command("sys").splitlines()
    for line in resultlines:
        words = line.split(":", 1)
        sysinfo[words[0].strip()] = words[1].strip()


def load_rules():
    global modules

    cmd_path_list = os.environ["PYKDUMPPATH"]
    path_list = cmd_path_list.split(':')
    source_path = ""
    for path in path_list:
        try:
            if os.path.exists(path + "/rules"):
                source_path = path + "/rules"
                load_rules_in_a_path(source_path)
        except:
            print ("Couldn't find %s/rules directory" % (path))

    return modules

def show_rules_list():
    global modules

    count = len(modules)
    if count == 0:
        print("No rules available for this vmcore")
        return

    print("-" * 75)
    for module in modules:
        crashcolor.set_color(crashcolor.BLUE)
        print("[%s]" % (module.__name__), end='')
        if module.is_major():
            crashcolor.set_color(crashcolor.GREEN)
        else:
            crashcolor.set_color(crashcolor.RESET)
        try:
            print(": %s" % (module.description()))
        except:
            print(": No description available")

        crashcolor.set_color(crashcolor.RESET)


    print("-" * 75)
    print("There are %d rules available for this vmcore" % (count))
    print("=" * 75)


def load_rules_in_a_path(source_path):
    global modules
    global sysinfo

    pysearchre = re.compile('.py$', re.IGNORECASE)
    rulefiles = filter(pysearchre.search, os.listdir(source_path))
    form_module = lambda fp: '.' + os.path.splitext(fp)[0]
    rules = map(form_module, rulefiles)
    importlib.import_module('rules')
    for rule in rules:
        if not rule.startswith('.__'):
            try:
                new_module = importlib.import_module(rule, package="rules")
                if new_module.add_rule(sysinfo) == True:
                   modules.append(new_module)
            except:
                print("Error in adding rule %s" % (rule))


def print_result(result_list):
    for result_dict in result_list:
        print("=" * 75)
        crashcolor.set_color(crashcolor.LIGHTRED)
        if "TITLE" in result_dict:
            print("ISSUE: %s" % result_dict["TITLE"])
        else:
            print("No title given")
        crashcolor.set_color(crashcolor.RESET)
        print("-" * 75)
        if "MSG" in result_dict:
            print(result_dict["MSG"])
        else:
            print("No message given")
        print("-" * 75)

        print("KCS:")
        if "KCS_TITLE" in result_dict:
            print("\t%s" % result_dict["KCS_TITLE"])
        else:
            print("\tNo subject for KCS")
        crashcolor.set_color(crashcolor.BLUE)
        if "KCS_URL" in result_dict:
            print("\t%s" % result_dict["KCS_URL"])
        else:
            print("\tNo URL for KCS")
        crashcolor.set_color(crashcolor.RESET)

        print("Resolution:")
        crashcolor.set_color(crashcolor.RED)
        if "RESOLUTION" in result_dict:
            print("\t%s" % result_dict["RESOLUTION"])
        else:
            print("\tNo resolution given")
        crashcolor.set_color(crashcolor.RESET)
        print("-" * 75)


def run_rules(options):
    global modules
    global sysinfo

    issue_count = 0

    for module in modules:
        try:
            if not options.do_all and not module.is_major():
                continue
            result_list = module.run_rule(sysinfo)
            if result_list != None:
                issue_count = issue_count + len(result_list)
                print_result(result_list)
        except:
            print("Error running rule %s" % (module))

    if issue_count > 0:
        print("*" * 75)
        crashcolor.set_color(crashcolor.RED | crashcolor.BLINK)
        print("\tWARNING: %d issue%s detected" %
              (issue_count, "s" if issue_count > 1 else ""))
        crashcolor.set_color(crashcolor.RESET)
        print("*" * 75)
    else:
        print("No issues detected")



def reload_rules():
    global modules

    for module in modules:
        try:
            print("Reloading [%s]" % (module.__name__), end='')
            module = importlib.reload(module)
            print("... DONE")
        except:
            print("... FAILED")

    print("Reloading DONE")


def autocheck():
    op = OptionParser()

    op.add_option("-a", "--all",
                  action="store_true",
                  dest="do_all",
                  default=False,
                  help="Do try all rules. default is doing major rules only")

    op.add_option("-l", "--list",
                  action="store_true",
                  dest="list",
                  default=False,
                  help="Shows the currently available rules")

    op.add_option("-r", "--reload",
                  action="store_true",
                  dest="reload",
                  default=False,
                  help="Re-load rules")


    (o, args) = op.parse_args()
    get_system_info()

    load_rules()

    if o.reload == True:
        reload_rules()
        sys.exit(0)


    if o.list == True:
        show_rules_list()
        sys.exit(0)

    run_rules(o)


if ( __name__ == '__main__'):
        autocheck()
