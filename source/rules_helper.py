
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
