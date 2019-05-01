"""
 Written by Daniel Sungju Kwon
"""

from __future__ import print_function
from __future__ import division

from pykdump.API import *

import sys
import os

BLACK = 1
RED = 2
GREEN = 3
YELLOW = 4
BLUE = 5
MAGENTA = 6
CYAN = 7
DARKGRAY = 8
LIGHTRED = 9
LIGHTGREEN = 10
LIGHTYELLOW = 11
LIGHTBLUE = 12
LIGHTMAGENTA = 13
LIGHTCYAN = 14
LIGHTGRAY = 15
WHITE = 16
RESET = 17

MAX_COLOR = WHITE

BOLD = 0x00100
BLINK = 0x00200
UNDERLINE = 0x00400
INVERT = 0x00800

MIN_MODE = BOLD
MAX_MODE = INVERT

COLOR_MASK = 0x00ff
MODE_MASK = 0xff00

bg_color_list = {
    BLACK : "\\u001b[40m",
    RED : "\\u001b[41m",
    GREEN : "\\u001b[42m",
    YELLOW : "\\u001b[43m",
    BLUE : "\\u001b[44m",
    MAGENTA : "\\u001b[45m",
    CYAN : "\\u001b[46m",
    LIGHTGRAY : "\\u001b[47m",
    DARKGRAY : "\\u001b[40;1m",
    LIGHTRED : "\\u001b[41;1m",
    LIGHTGREEN : "\\u001b[42;1m",
    LIGHTYELLOW : "\\u001b[43;1m",
    LIGHTBLUE : "\\u001b[44;1m",
    LIGHTMAGENTA : "\\u001b[45;1m",
    LIGHTCYAN : "\\u001b[46;1m",
    WHITE : "\\u001b[47;1m",
    RESET : "\\u001b[0m",
}


color_list = {
    BLACK : "\\u001b[30m",
    RED : "\\u001b[31m",
    GREEN : "\\u001b[32m",
    YELLOW : "\\u001b[33m",
    BLUE : "\\u001b[34m",
    MAGENTA : "\\u001b[35m",
    CYAN : "\\u001b[36m",
    LIGHTGRAY : "\\u001b[37m",
    DARKGRAY : "\\u001b[30;1m",
    LIGHTRED : "\\u001b[31;1m",
    LIGHTGREEN : "\\u001b[32;1m",
    LIGHTYELLOW : "\\u001b[33;1m",
    LIGHTBLUE : "\\u001b[34;1m",
    LIGHTMAGENTA : "\\u001b[35;1m",
    LIGHTCYAN : "\\u001b[36;1m",
    WHITE : "\\u001b[37;1m",
    RESET : "\\u001b[0m",
    BOLD : "\\u001b[1m",
    BLINK : "\\033[5m",
    UNDERLINE : "\\u001b[4m",
    INVERT : "\\u001b[7m",
}

def set_bg_color(color):
    if not sys.stdout.isatty():
        return

    color_ansi_code = ""
    if color in bg_color_list:
        color_ansi_code = bg_color_list[color]

    if len(color_ansi_code) > 0:
        result_str = exec_crash_command("gdb echo " + color_ansi_code)
        print (result_str, end='')


def set_color(color_mix):
    if not sys.stdout.isatty():
        return

    color = color_mix & COLOR_MASK
    mode = color_mix & MODE_MASK

    color_ansi_code = ""
    # Set text color
    if color in color_list:
        color_ansi_code = color_list[color]

    # Set text mode
    for cur_mode in range(MIN_MODE, MAX_MODE, MIN_MODE):
        cur_color = mode & cur_mode
        if cur_color in color_list:
            color_ansi_code = color_ansi_code + color_list[cur_color]

    if len(color_ansi_code) > 0:
        result_str = exec_crash_command("gdb echo " + color_ansi_code)
        print (result_str, end='')
