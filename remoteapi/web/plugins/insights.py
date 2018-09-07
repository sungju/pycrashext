"""
Written by Daniel Sungju Kwon

It is providing interface to use insights with the data
collected from vmcore.
"""
from flask import Flask
from flask import request
import re
import os
import base64
import subprocess


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
    try:
        process = subprocess.Popen('python insights_call.py',
                                   shell=True,
                                   stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        result = process.communicate(input=str.encode(get_data_from_post("data")))
        return result
    except Exception as e:
        return str(e)

