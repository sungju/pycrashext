"""
Written by Daniel Sungju Kwon

This is loading extra plugins which can be added at runtime
"""
import os
import sys
import re
import importlib

def load_plugins(app):
    pysearchre = re.compile('.py$', re.IGNORECASE)
    pluginfiles = filter(pysearchre.search,
                           os.listdir(os.path.join(os.path.dirname(__file__),
                                                 'plugins')))
    form_module = lambda fp: '.' + os.path.splitext(fp)[0]
    plugins = map(form_module, pluginfiles)
    # import parent module / namespace
    importlib.import_module('plugins')
    modules = []
    for plugin in plugins:
             if not plugin.startswith('.__'):
                 try:
                     new_module = importlib.import_module(plugin, package="plugins")
                     new_module.add_plugin_rule(app)
                     modules.append(new_module)
                 except:
                     pass
    return modules
