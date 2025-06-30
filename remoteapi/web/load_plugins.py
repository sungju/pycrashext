"""
Written by Daniel Sungju Kwon

This is loading extra plugins which can be added at runtime
"""

import os
import sys
import re
import importlib

def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


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
                     eprint("Trying to load module '%s'..." % plugin)
                     new_module = importlib.import_module(plugin, package="plugins")
                     eprint("module '%s' is loaded" % plugin)
                     new_module.add_plugin_rule(app)
                     modules.append(new_module)
                     eprint("rules from '%s' are added" % plugin)
                 except Exception as e:
                     eprint("Module loading error for %s : %s" % (plugin, e))
                     pass
    return modules
