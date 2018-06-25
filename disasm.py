from __future__ import print_function
import sys
import base64
import requests as r
import os
from optparse import OptionParser


orig_asm = "".join(sys.stdin.readlines()).encode()
encoded_asm = base64.b64encode(orig_asm)

encode_url = os.environ['CRASHEXT_SERVER'] + '/api/disasm'

# Additional options that can pass to the server
op = OptionParser()
op.add_option("-g", "--graph",
              action="store_true",
              dest="graph",
              default=False,
              help="display jump graph on the left")

(o, args) = op.parse_args()


# Draw jump lines
draw_graph = ""
if o.graph:
    draw_graph = "draw"

data = {"asm_str" : encoded_asm, "jump_graph" : draw_graph}
res = r.post(encode_url, data = data).text

# Print the result
print (res, end='')
