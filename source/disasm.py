
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


    if encode_url == "":
        res = "\tCRASHEXT_SERVER environment variable not configured\n\n"\
               + orig_asm
        print(res, end='')
        return


    # Additional options that can pass to the server
    op = OptionParser()
    op.add_option("-f", "--full",
                  action="store_true",
                  dest="fullsource",
                  default=False,
                  help="Display full source code")

    op.add_option("-s", "--sourceonly",
                  action="store_true",
                  dest="sourceonly",
                  default=False,
                  help="Shows source lines only")

    (o, args) = op.parse_args()


    full_source = ""
    if o.fullsource:
        full_source = "fullsource"

    source_only = ""
    if o.sourceonly:
        source_only = "sourceonly"

    data = {"asm_str" : encoded_asm, "full_source" : full_source,
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
