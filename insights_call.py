from __future__ import print_function
import sys
import base64
import requests as r
import os
from optparse import OptionParser


def insights_call():
    orig_data = "".join(sys.stdin.readlines()).encode()
    encoded_data = base64.b64encode(orig_data)

    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/insights'
    except:
        encode_url = ""

    data = {"data" : encoded_data }
    try:
        res = r.post(encode_url, data = data).text
    except r.exceptions.RequestException as e:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_data
    except:
        res = "\tUnexpected error:" + sys.exc_info()[0] + \
              "\n" + orig_data

    # Print the result
    print (res, end='')


if ( __name__ == '__main__'):
    insights_call()
