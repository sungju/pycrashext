import json
import sys
import base64
import requests as r
import os
from optparse import OptionParser


def ai_send():
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

    encoded_query = base64.b64encode(orig_query.encode())

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


    try:
        res = r.post(encode_url, data = data).text
        parsed = json.loads(res)
    except r.exceptions.RequestException as e:
        res = "\tServer is not reachable.\n" + \
              "\tServer address is <" + encode_url + ">" + \
              "\n" + orig_query
    except:
        res = "\tUnexpected error:" + sys.exc_info()[0] + \
              "\n" + orig_query

    # Print the result
    print (parsed['response'], end='')



if ( __name__ == '__main__'):
    ai_send()
