"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

from LinuxDump import Tasks, sysctl

import sys
import operator
import os
from os.path import expanduser
import time

import crashcolor
import crashhelper

import json
import base64
import urllib.parse
import urllib.request
import meminfo


sysinfo={}

def get_system_info():
    global sysinfo

    resultlines = exec_crash_command("sys").splitlines()
    for line in resultlines:
        words = line.split(":")
        sysinfo[words[0].strip()] = words[1].strip()


def check_sysctl():
    ctbl = sysctl.getCtlTables()
    names = sorted(ctbl.keys())
    result_str = ""

    for n in names:
        ct = ctbl[n]
        try:
            dall_val = sysctl.getCtlData(ct)
            if type(dall_val) is list:
                dall = ""
                for d_one in dall_val:
                    dall = dall + "{0}".format(d_one) + " "
            else:
                dall = dall_val
        except:
            dall = '(?)'
        result_str = result_str + ("%s = %s\n" % (n.ljust(20), dall))

    return result_str


def get_sysdata_dict():
    global sysinfo
    global page_size

    page_size = 1 << get_page_shift()
    dict = {}
    get_system_info()

    machine = sysinfo["MACHINE"].split()[0]
    dict["hostname"] = sysinfo["NODENAME"]
    dict["uname"] = "Linux %s %s %s %s %s %s GNU/Linux" % \
            (sysinfo["NODENAME"], sysinfo["RELEASE"], sysinfo["VERSION"],
             machine, machine, machine)
    dict["dmesg"] = exec_crash_command("log")
    dict["sysctl"] = check_sysctl()
    dict["meminfo"] = get_meminfo()

    return dict


def exec_insights(o, args, cmd_path_list):
    sysdata_dict = get_sysdata_dict()
    sysdata_str = json.dumps(sysdata_dict)
    cmd_options = ""

    try:
        remoteapi_url = os.environ['CRASHEXT_SERVER'] + '/api/insights'
    except:
        remoteapi_url = ""

    data = {"data" : base64.b64encode(sysdata_str.encode()) }
    try:
        url_data = urllib.parse.urlencode(data)
        req = urllib.request.Request(remoteapi_url, url_data.encode())
        response = urllib.request.urlopen(req)
        res = response.read()
    except Exception as e:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + remoteapi_url + ">" + \
              "\n" + str(e)

    print(res)


def insights():
    op = OptionParser()

    (o, args) = op.parse_args()
    exec_insights(o, args, os.environ["PYKDUMPPATH"])


if ( __name__ == '__main__'):
    insights()
