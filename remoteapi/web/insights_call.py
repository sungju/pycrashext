"""
Written by Daniel Sungju Kwon

It is providing interface to use insights with the data
collected from vmcore.
"""
import re
import os
import sys
import base64
import subprocess
import json


### Insights related modules
### ------------------------
from insights import dr
#from insights.formats.text import HumanReadableFormat as Formatter
from insights.formats._json import JsonFormatter as Formatter

from insights.specs import Specs
from insights.tests import context_wrap
### ------------------------

def insights_call():
    data_str = ''.join(sys.stdin.readlines())
    decoded_str = base64.b64decode(data_str)
    data_dict = json.loads(decoded_str)

    if "INSIGHTS_RULES" in os.environ:
        rules_list = os.environ["INSIGHTS_RULES"].split(":")
        for rule_path in rules_list:
            sys.path.append(rule_path)
            dr.load_components(os.path.basename(rule_path))

    try:
        dr.load_components("insights.specs.default")
        broker = dr.Broker()
        broker[Specs.hostname] = context_wrap(data_dict["hostname"])
        broker[Specs.uname] = context_wrap(data_dict["uname"])
        broker[Specs.dmesg] = context_wrap(data_dict["dmesg"])
        with Formatter(broker):
            dr.run(broker=broker)
    except Exception as e:
        return str(e)


if ( __name__ == '__main__'):
    insights_call()
