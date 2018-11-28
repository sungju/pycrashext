from __future__ import print_function
import sys
import base64
import requests as r
import os
from optparse import OptionParser


def disasm():
    orig_asm = "".join(sys.stdin.readlines()).encode()
    encoded_asm = base64.b64encode(orig_asm)

    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/disasm'
    except:
        encode_url = ""

    # Additional options that can pass to the server
    op = OptionParser()
    op.add_option("-g", "--graph",
                  action="store_true",
                  dest="graph",
                  default=False,
                  help="display jump graph on the left")

    op.add_option("-f", "--full",
                  action="store_true",
                  dest="fullsource",
                  default=False,
                  help="Display full source code")

    op.add_option("-j", "--jump",
                  action="store",
                  type="string",
                  dest="jump_op_list",
                  default="",
                  help="Shows graph for the specified jump operations only")


    op.add_option("-s", "--sourceonly",
                  action="store_true",
                  dest="sourceonly",
                  default=False,
                  help="Shows source lines only")

    (o, args) = op.parse_args()


    # Draw jump lines
    draw_graph = ""
    if o.graph:
        draw_graph = "draw"

    full_source = ""
    if o.fullsource:
        full_source = "fullsource"

    source_only = ""
    if o.sourceonly:
        source_only = "sourceonly"


    jump_op_list = ""
    if o.jump_op_list != "":
        jump_op_list = o.jump_op_list

    data = {"asm_str" : encoded_asm, "jump_graph" : draw_graph,
            "full_source" : full_source, "jump_op_list" : jump_op_list,
            "source_only" : source_only}
    try:
        res = r.post(encode_url, data = data).text
    except r.exceptions.RequestException as e:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_asm
    except:
        res = "\tUnexpected error:" + sys.exc_info()[0] + \
              "\n" + orig_asm

    # Print the result
    print (res, end='')



if ( __name__ == '__main__'):
    disasm()
