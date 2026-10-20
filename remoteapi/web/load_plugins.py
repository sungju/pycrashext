"""
Dynamically loads the remoteapi route plugins under ./plugins, then any
external plugins found in the directories PYCRASHEXT_PLUGIN_PATH lists.

An external plugin is an ordinary plugin file - a module with
add_plugin_rule(app) - kept outside this repository, so site-specific
endpoints can be added without touching or shipping them here.

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import sys
import re
import hashlib
import importlib
import importlib.util

PLUGIN_PATH_ENV = 'PYCRASHEXT_PLUGIN_PATH'

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
    modules.extend(load_external_plugins(app, os.environ.get(PLUGIN_PATH_ENV, '')))
    return modules


def split_plugin_path(path_value):
    """The existing directories in a PATH-style value, in order, without repeats."""
    dirs = []
    for entry in (path_value or '').split(os.pathsep):
        entry = entry.strip()
        if not entry:
            continue
        real = os.path.realpath(os.path.expanduser(entry))
        if not os.path.isdir(real):
            eprint("%s: '%s' is not a directory, skipped" % (PLUGIN_PATH_ENV, entry))
            continue
        if real not in dirs:
            dirs.append(real)
    return dirs


def external_module_name(plugin_dir, filename):
    """A module name unique to this file, so two directories can both have 'kcs.py'."""
    tag = hashlib.sha1(plugin_dir.encode('utf-8')).hexdigest()[:8]
    return 'pycrashext_ext_%s_%s' % (tag, os.path.splitext(filename)[0])


def forget_modules_in(plugin_dir):
    """Drop cached modules loaded from 'plugin_dir', so /reload imports helpers afresh."""
    prefix = plugin_dir + os.sep
    for name, module in list(sys.modules.items()):
        path = getattr(module, '__file__', None)
        if path and os.path.realpath(path).startswith(prefix):
            del sys.modules[name]


def load_external_plugins(app, path_value):
    """Load every *.py in each PYCRASHEXT_PLUGIN_PATH directory and add its rules.

    A file whose name starts with '_' is a helper, not a plugin; the
    directory is put on sys.path so plugins can import such helpers.
    A plugin that fails to load, or whose route clashes with one already
    registered, is reported and skipped; the rest still load.
    """
    modules = []
    for plugin_dir in split_plugin_path(path_value):
        if plugin_dir not in sys.path:
            sys.path.insert(0, plugin_dir)
        forget_modules_in(plugin_dir)
        for filename in sorted(os.listdir(plugin_dir)):
            if not filename.endswith('.py') or filename.startswith('_'):
                continue
            file_path = os.path.join(plugin_dir, filename)
            try:
                eprint("Trying to load external plugin '%s'..." % file_path)
                spec = importlib.util.spec_from_file_location(
                    external_module_name(plugin_dir, filename), file_path)
                new_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(new_module)
                new_module.add_plugin_rule(app)
                modules.append(new_module)
                eprint("rules from '%s' are added" % file_path)
            except Exception as e:
                eprint("External plugin loading error for %s : %s" % (file_path, e))
    return modules
