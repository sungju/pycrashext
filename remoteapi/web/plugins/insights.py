"""
Written by Daniel Sungju Kwon

It is providing interface to use insights with the data
collected from vmcore.
"""
from flask import Flask
from flask import request
import re
import os
import sys
import base64
import subprocess
import json
import six


### Insights related modules
### ------------------------
from insights import dr
#from insights.formats.text import HumanReadableFormat as Formatter
from insights.formats._json import JsonFormat as Formatter

from insights.specs import Specs
from insights.tests import context_wrap
### ------------------------

def insights_call(data_str):
    decoded_str = base64.b64decode(data_str)
    data_dict = json.loads(decoded_str)

    try:
        if "INSIGHTS_RULES" in os.environ:
            rules_list = os.environ["INSIGHTS_RULES"].split(":")
            for rule_path in rules_list:
                if rule_path not in sys.path:
                    sys.path.append(rule_path)
                dr.load_components(os.path.basename(rule_path))
    except Exception as e:
        return str(e)

    try:
        dr.load_components("insights.specs.default")
        broker = dr.Broker()
        broker[Specs.hostname] = context_wrap(data_dict["hostname"])
        broker[Specs.uname] = context_wrap(data_dict["uname"])
        broker[Specs.dmesg] = context_wrap(data_dict["dmesg"])
        broker[Specs.messages] = context_wrap(data_dict["dmesg"])
        broker[Specs.sysctl] = context_wrap(data_dict["sysctl"])
        broker[Specs.meminfo] = context_wrap(data_dict["meminfo"])

        output = six.StringIO()
        with Formatter(broker, stream=output):
            dr.run(broker=broker)

        output.seek(0)
        data = output.read()
        return data
    except Exception as e:
        return str(e)


def add_plugin_rule(app):
    app.add_url_rule('/api/insights', 'insights', insights, methods=['POST'])


    return False

def get_data_from_post(entity):
    result = ""
    try:
        result = request.form[entity]
    except:
        result = ""

    return result


def insights():
    return insights_call(get_data_from_post("data"))
