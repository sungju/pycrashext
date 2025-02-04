"""
Written by Daniel Sungju Kwon

It gets some help from specified AI engine for the remote data
"""
from flask import Flask
from flask import request
import re
import os
import base64
import subprocess


def add_plugin_rule(app):
    app.add_url_rule('/api/ai', 'ai', ai_analyse, methods=['POST'])


AI_CMD='ollama'
AI_RUN='run'
AI_MODEL='llama3.2'
#AI_MODEL='deepseek-r1'

def ai_analyse():
    # First line can be used to identify kernel version
    try:
        query_str = request.form["query_str"]
    except:
        return 'error getting query data'

    try:
        model_str = request.form["model_str"]
        AI_MODEL = model_str
    except:
        AI_MODEL='llama3.2'

    try:
        query_str = base64.b64decode(query_str).decode("utf-8")
    except:
        return 'error found in decoding base64'

    result_str = ""
    try:
        result = subprocess.run([AI_CMD, AI_RUN, AI_MODEL, query_str],
                                capture_output=True)
        result_str = result.stdout.decode()
    except:
        result_str = result.stderr.decode()

    model_used_str = "RESULT FROM THE AI MODEL <" + AI_MODEL + ">"

    return query_str + "\n\n" + model_used_str + "\n" + \
            ("=" * len(model_used_str)) + "\n" + result_str.rstrip()
