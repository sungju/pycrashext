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

import html2text
import urllib.request
from bs4 import BeautifulSoup
import re

def get_inst(url):
	with urllib.request.urlopen(url) as response:
		html = response.read()

	h = html2text.HTML2Text()
	h.ignore_links = True
	data = h.handle(html.decode("utf-8")).replace("¶", "")

	return data


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


fetch_instructions("x86asm.txt")
