#!/usr/bin/env/python
# --------------------------------------------------------------------
# (C) Copyright 2020
#
# Author: Daniel Sungju Kwon <sungju.kwon@gmail.com>
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

import urllib.request
from bs4 import BeautifulSoup
import re
import sys


def get_table_str(table):
    data = []
    max_len = {}
    rowspan = 0
    rowspan_idx = -1
    for row in table.find_all("tr"):
        columns = []
        idx = 0
        column_list = row.find_all("th")
        column_list = column_list + row.find_all("td")
        for column in column_list:
            if rowspan > 0 and idx == rowspan_idx:
                columns.append("")
                idx = idx + 1
                rowspan = rowspan - 1

            text = get_text(column)
            columns.append(text)
            mylen = len(text)
            if idx in max_len:
                if mylen > max_len[idx]:
                    max_len[idx] = mylen
            else:
                max_len[idx] = mylen

            tmp_rowspan = column.get("rowspan")
            if tmp_rowspan is not None:
                rowspan = int(tmp_rowspan) - 1
                rowspan_idx = idx

            idx = idx + 1

        data.append(columns)


    result = ""
    for row in data:
        idx = 0
        for column in row:
            result = result + ' {0:{align}{width}} '.format(column, align='<', width=max_len[idx])
            idx = idx + 1
        result = result.strip() + "\n"

    return result


def get_text(entry):
    result = entry.text.strip()
    result = re.sub('\t', ' ', result)
    result = re.sub('\n', ' ', result)
    result = re.sub(' +', ' ', result)
    return result


def get_inst(url):
    html = urllib.request.urlopen(url).read().decode("utf-8").replace("¶", "")
    soup = BeautifulSoup(html, features="lxml")
    body = soup.find("body")
    child_list = body.contents
    result = ""
    for child in child_list:
        if child.name == "h1":
            result = result + ("# %s #\n" % (get_text(child)))
        elif child.name == "h2":
            result = result + ("## %s ##\n" % (get_text(child)))
        elif child.name == "p":
            result = result + ("%s\n\n" % (get_text(child)))
        elif child.name == "pre":
            result = result + ("%s\n\n" % (child.text.strip()))
        elif child.name == "table":
            result = result + ("\n %s\n" % (get_table_str(child)))

    return result


def fetch_instructions(target_file):
    source_url = "https://www.felixcloutier.com/x86/index.html"
    html = urllib.request.urlopen(source_url).read()
    soup = BeautifulSoup(html, features="lxml")
    with open(target_file, 'w') as f:
        f.write("%s\n" % ("-" * 50))
        f.write("From %s\n" % source_url)
        f.write("%s\n\n" % ("-" * 50))

        f.write("ARCHITECTURE: i386 i686 x86_64 athlon\n")
        for link in soup.findAll('a'):
            addr = link.get('href')
            if addr.startswith("./"):
                addr = addr.replace("./", "https://www.felixcloutier.com/x86/")
                data = get_inst(addr)
                inst = link.text
                print(inst)
                f.write("INSTRUCTION: %s\n" % inst)
                f.write("%s\n" % data[data.find("# %s" % inst):-1])
                f.write("END_INSTRUCTION: %s\n\n\n" % inst)

        f.write("END_ARCHITECTURE: i386 i686 x86_64 athlon\n")


fetch_instructions("x86asm.data")
