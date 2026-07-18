"""
Helper for the 'ai' command: sends collected data to the remoteapi /api/ai endpoint and renders the reply.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import json
import sys
import base64
import urllib.request
import urllib.parse
import urllib.error
import socket
import os
from optparse import OptionParser


def ai_send():
    # Parse options before checking environment so we don't reference orig_query
    # before assignment and keep behavior consistent.
    try:
        encode_url = os.environ['CRASHEXT_SERVER'] + '/api/ai'
    except:
        encode_url = ""

    # Additional options that can pass to the server
    op = OptionParser()
    op.add_option("-e", "--engine",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_engine",
                  help="Set AI engine to run")

    op.add_option("-i", "--input",
                  action="store",
                  type="string",
                  default="",
                  dest="input_file",
                  help="Use file for input data")

    op.add_option("-m", "--model",
                  action="store",
                  type="string",
                  default="",
                  dest="ai_model",
                  help="Set AI model to run")

    op.add_option("-r", "--reset",
                  action="store_true",
                  dest="reset",
                  default=False,
                  help="Reset AI prompt history")

    op.add_option("-t", "--taskid",
                  action="store",
                  type="string",
                  default="",
                  dest="taskid",
                  help="vmcore taskid")
    (o, args) = op.parse_args()

    orig_query = "".join(sys.stdin.readlines())
    if o.input_file != "":
        try:
            with open(o.input_file) as fp:
                orig_query = "".join(fp.readlines())

            os.remove(o.input_file)
        except:
            pass

    if encode_url == "":
        res = "\tCRASHEXT_SERVER environment variable not configured\n\n" \
              + orig_query
        print(res, end='')
        return

    encoded_query = base64.b64encode(orig_query.encode()).decode("ascii")

    data = {"query" : encoded_query}
    data["session_id"] = o.taskid

    # AI Engine
    try:
        engine_str = os.environ['AI_ENGINE']
        if engine_str != '':
            data['engine'] = engine_str
    except:
        pass

    if o.ai_engine != "":
        data['engine'] = o.ai_engine


    # AI model
    try:
        model_str = os.environ['AI_MODEL']
        if model_str != '':
            data['model'] = model_str
    except:
        pass

    if o.ai_model != "":
        data['model'] = o.ai_model

    if o.reset:
        data['reset'] = 'reset'

    parsed = None
    try:
        timeout_seconds = int(os.environ.get('AI_REQUEST_TIMEOUT', '30'))
        encoded_data = urllib.parse.urlencode(data).encode('utf-8')
        req = urllib.request.Request(encode_url, data=encoded_data, method='POST')
        response = urllib.request.urlopen(req, timeout=timeout_seconds)
        res = response.read().decode('utf-8')
        parsed = json.loads(res)
    except socket.timeout:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_query
    except urllib.error.HTTPError as e:
        res = e.read().decode('utf-8')
    except urllib.error.URLError as e:
        if isinstance(e.reason, socket.timeout):
            res = "\tServer is not reachable.\n" + \
                  "\tServer address is <" + encode_url + ">" + \
                  "\n" + orig_query
        else:
            res = "\tServer request failed: " + str(e.reason) + \
                  "\n" + orig_query
    except ValueError:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_query
    except:
        res = "\tUnexpected error.\n" + str(sys.exc_info()[0]) + \
              "\n" + orig_query

    # Print the result
    if parsed is None:
        print(res, end='')
        return

    try:
        from rich.console import Console
        from rich.markdown import Markdown
        try:
            code_theme = os.environ['CODE_THEME']
        except:
            code_theme = "tango"

        if "response" not in parsed:
            raise KeyError("response")

        console = Console(color_system="truecolor")
        console.print(Markdown(parsed['response'], code_theme=code_theme))
        #console.print(Markdown(parsed['response'], code_theme="manni"))
    except:
        if isinstance(parsed, dict) and "response" in parsed:
            print(parsed["response"])
        else:
            print(res, end='')
        print("\nNotes) 'pip install rich' can enhance the output", end='')


if ( __name__ == '__main__'):
    ai_send()
