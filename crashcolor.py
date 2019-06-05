#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2018-2019 Red Hat, Inc.
#
# Author: Daniel Sungju Kwon <dkwon@redhat.com>
#
# This provides ANSI features such as color output and cursor manipulation.
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

import sys
import os


def run_ansi_code(ansi_code_str):
    print (ansi_code_str, end='')


#------------------------------------------------------------------------
# Color related functions
#------------------------------------------------------------------------
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
    BLACK : u"\u001b[40m",
    RED : u"\u001b[41m",
    GREEN : u"\u001b[42m",
    YELLOW : u"\u001b[43m",
    BLUE : u"\u001b[44m",
    MAGENTA : u"\u001b[45m",
    CYAN : u"\u001b[46m",
    LIGHTGRAY : u"\u001b[47m",
    DARKGRAY : u"\u001b[40;1m",
    LIGHTRED : u"\u001b[41;1m",
    LIGHTGREEN : u"\u001b[42;1m",
    LIGHTYELLOW : u"\u001b[43;1m",
    LIGHTBLUE : u"\u001b[44;1m",
    LIGHTMAGENTA : u"\u001b[45;1m",
    LIGHTCYAN : u"\u001b[46;1m",
    WHITE : u"\u001b[47;1m",
    RESET : u"\u001b[0m",
}


color_list = {
    BLACK : u"\u001b[30m",
    RED : u"\u001b[31m",
    GREEN : u"\u001b[32m",
    YELLOW : u"\u001b[33m",
    BLUE : u"\u001b[34m",
    MAGENTA : u"\u001b[35m",
    CYAN : u"\u001b[36m",
    LIGHTGRAY : u"\u001b[37m",
    DARKGRAY : u"\u001b[30;1m",
    LIGHTRED : u"\u001b[31;1m",
    LIGHTGREEN : u"\u001b[32;1m",
    LIGHTYELLOW : u"\u001b[33;1m",
    LIGHTBLUE : u"\u001b[34;1m",
    LIGHTMAGENTA : u"\u001b[35;1m",
    LIGHTCYAN : u"\u001b[36;1m",
    WHITE : u"\u001b[37;1m",
    RESET : u"\u001b[0m",
    BOLD : u"\u001b[1m",
    BLINK : u"\u001b[5m",
    UNDERLINE : u"\u001b[4m",
    INVERT : u"\u001b[7m",
}


def set_bg_color(color):
    if not sys.stdout.isatty():
        return

    if color in bg_color_list:
        color_ansi_code = bg_color_list[color]


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
        run_ansi_code(color_ansi_code)


def get_color(color):
    if color in color_list:
        return color_list[color]

    return ""


#------------------------------------------------------------------------
# Cursor related functions
#------------------------------------------------------------------------
CURSOR_RESET = 0
CURSOR_UP = 1
CURSOR_DOWN = 2
CURSOR_RIGHT = 3
CURSOR_LEFT = 4

cursor_code_list = {
    CURSOR_RESET : u"\u001b[1000D",
    CURSOR_UP : u"\u001b[%dA",
    CURSOR_DOWN : u"\u001b[%dB",
    CURSOR_RIGHT : u"\u001b[%dC",
    CURSOR_LEFT : u"\u001b[%dD",
}


def change_cursor(cursor_type, by=0):
    if not sys.stdout.isatty():
        return

    if cursor_type in cursor_code_list:
        cursor_code = cursor_code_list[cursor_type]
        if cursor_type != CURSOR_RESET:
            cursor_code = cursor_code % (by)
        sys.stdout.flush()
        run_ansi_code(cursor_code)


def cursor_reset():
    change_cursor(CURSOR_RESET)


def cursor_up(by=1):
    change_cursor(CURSOR_UP, by)


def cursor_down(by=1):
    change_cursor(CURSOR_DOWN, by)


def cursor_left(by=1):
    change_cursor(CURSOR_LEFT, by)


def cursor_right(by=1):
    change_cursor(CURSOR_RIGHT, by)


CURSOR_POS = u"\u001b[%d;%dH"

def set_cursor(xpos, ypos):
    cursor_pos_str = CURSOR_POS % (ypos, xpos)
    run_ansi_code(cursor_pos_str)


#------------------------------------------------------------------------
# Clear related functions
#------------------------------------------------------------------------
CLEAR_SCREEN_AFTER = 0
CLEAR_SCREEN_BEFORE = 1
CLEAR_SCREEN_ALL = 2

clear_screen_list = {
    CLEAR_SCREEN_AFTER : u"\u001b[0J",
    CLEAR_SCREEN_BEFORE: u"\u001b[1J",
    CLEAR_SCREEN_ALL : u"\u001b[2J",
}

CLEAR_LINE_AFTER = 0
CLEAR_LINE_BEFORE = 1
CLEAR_LINE_ALL = 2


clear_line_list = {
    CLEAR_LINE_AFTER : u"\u001b[0K",
    CLEAR_LINE_BEFORE : u"\u001b[1K",
    CLEAR_LINE_ALL : u"\u001b[2K",
}


def clear_screen_to(mode):
    if not sys.stdout.isatty():
        return

    if mode in clear_screen_list:
        clear_code = clear_screen_list[mode]
        run_ansi_code(clear_code)


def clear_screen_before():
    clear_screen_to(CLEAR_SCREEN_BEFORE)


def clear_screen_after():
    clear_screen_to(CLEAR_SCREEN_AFTER)


def clear_screen():
    clear_screen_to(CLEAR_SCREEN_ALL)


def clear_line_to(mode):
    if not sys.stdout.isatty():
        return

    if mode in clear_line_list:
        clear_code = clear_line_list[mode]
        run_ansi_code(clear_code)


def clear_line_before():
    clear_line_to(CLEAR_LINE_BEFORE)


def clear_line_after():
    clear_line_to(CLEAR_LINE_AFTER)


def clear_line():
    clear_line_to(CLEAR_LINE_ALL)

