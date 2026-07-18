"""
Shared helpers for the autocheck detection rules under ./rules.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

from pykdump.API import *

from LinuxDump import Tasks

import crashhelper
import meminfo


def get_data(basic_data, command):
    return exec_crash_command(command)


def get_symbol(symbol):
    return readSymbol(symbol)


def is_symbol_exists(symbol):
    return symbol_exists(symbol)


def get_size_str(size):
    return meminfo.get_size_str(size)


def get_page_size():
    return meminfo.get_page_size()


def get_page_shift():
    return meminfo.get_page_shift()
