import sys
import base64
import requests as r


orig_asm = "".join(sys.stdin.readlines()).encode()
encoded_asm = base64.b64encode(orig_asm)

encode_url = 'http://minilab.usersys.redhat.com:5000/api/disasm'
data = {"asm_str" : encoded_asm}
res = r.post(encode_url, data = data).text
print (res)
