from __future__ import print_function
import sys
import base64
import requests as r
import os


orig_asm = "".join(sys.stdin.readlines()).encode()
encoded_asm = base64.b64encode(orig_asm)

encode_url = os.environ['CRASHEXT_SERVER'] + '/api/disasm'
data = {"asm_str" : encoded_asm}
res = r.post(encode_url, data = data).text
print (res, end='')
