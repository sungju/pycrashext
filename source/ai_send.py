from __future__ import print_function
import sys
import base64
import requests as r
import os
from optparse import OptionParser


def ai_send():
    orig_query = "".join(sys.stdin.readlines())
    encoded_query = base64.b64encode(orig_query.encode())

    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/ai'
    except:
        encode_url = ""


    if encode_url == "":
        res = "\tCRASHEXT_SERVER environment variable not configured\n\n"\
               + orig_query
        print(res, end='')
        return


    # Additional options that can pass to the server
    op = OptionParser()
    (o, args) = op.parse_args()


    data = {"query_str" : encoded_query}
    try:
        res = r.post(encode_url, data = data).text
    except r.exceptions.RequestException as e:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_query
    except:
        res = "\tUnexpected error:" + sys.exc_info()[0] + \
              "\n" + orig_query

    # Print the result
    print (res, end='')



if ( __name__ == '__main__'):
    ai_send()
