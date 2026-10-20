"""
Checks for PYCRASHEXT_PLUGIN_PATH, the external remoteapi plugin directories.

Run directly: python3 remoteapi/web/load_plugins_test.py
(Flask is not needed: the plugins here register on a stand-in app.)

Written by Sungju Kwon <sungju.kwon@gmail.com>
"""

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from load_plugins import load_external_plugins


class FakeApp(object):
    """Records routes, and refuses a second view under one endpoint as Flask does."""
    def __init__(self):
        self.routes = {}

    def add_url_rule(self, rule, endpoint, view_func, methods=None):
        if endpoint in self.routes:
            raise AssertionError("View function mapping is overwriting an "
                                 "existing endpoint function: %s" % endpoint)
        self.routes[endpoint] = (rule, view_func)


PLUGIN = '''
def view():
    return %(answer)r

def add_plugin_rule(app):
    app.add_url_rule('/api/%(endpoint)s', %(endpoint)r, view, methods=['POST'])
'''


def write(path, text):
    with open(path, 'w') as f:
        f.write(text)


def make_plugin(plugin_dir, filename, endpoint, answer='ok'):
    write(os.path.join(plugin_dir, filename), PLUGIN % {'endpoint': endpoint, 'answer': answer})


def make_dir(root, name):
    path = os.path.join(root, name)
    os.makedirs(path)
    return path


def check_unset_loads_nothing(root):
    app = FakeApp()
    assert load_external_plugins(app, '') == [] and app.routes == {}


def check_loads_plugins_from_every_directory(root):
    a, b = make_dir(root, 'a'), make_dir(root, 'b')
    make_plugin(a, 'kcs.py', 'kcs')
    make_plugin(b, 'jira.py', 'jira')
    app = FakeApp()
    modules = load_external_plugins(app, os.pathsep.join([a, b]))
    assert len(modules) == 2
    assert sorted(app.routes) == ['jira', 'kcs'], app.routes
    assert app.routes['kcs'][0] == '/api/kcs'


def check_same_file_name_in_two_directories(root):
    a, b = make_dir(root, 'a'), make_dir(root, 'b')
    make_plugin(a, 'search.py', 'search_a', 'from a')
    make_plugin(b, 'search.py', 'search_b', 'from b')
    app = FakeApp()
    load_external_plugins(app, os.pathsep.join([a, b]))
    assert app.routes['search_a'][1]() == 'from a'
    assert app.routes['search_b'][1]() == 'from b'


def check_helpers_are_importable_not_loaded(root):
    d = make_dir(root, 'site')
    write(os.path.join(d, '_extcmd_helper_xyz.py'), 'ANSWER = "via helper"\n')
    write(os.path.join(d, 'kcs.py'),
          'import _extcmd_helper_xyz\n'
          'def view():\n    return _extcmd_helper_xyz.ANSWER\n'
          'def add_plugin_rule(app):\n'
          '    app.add_url_rule("/api/kcs", "kcs", view)\n')
    app = FakeApp()
    load_external_plugins(app, d)
    assert list(app.routes) == ['kcs'], app.routes
    assert app.routes['kcs'][1]() == 'via helper'


def check_broken_plugin_does_not_stop_the_rest(root):
    d = make_dir(root, 'site')
    write(os.path.join(d, 'a_broken.py'), 'raise RuntimeError("boom")\n')
    write(os.path.join(d, 'b_norule.py'), 'x = 1\n')
    make_plugin(d, 'c_good.py', 'good')
    app = FakeApp()
    modules = load_external_plugins(app, d)
    assert len(modules) == 1 and list(app.routes) == ['good'], app.routes


def check_clashing_endpoint_is_skipped(root):
    d = make_dir(root, 'site')
    make_plugin(d, 'git2.py', 'git')
    app = FakeApp()
    app.add_url_rule('/api/git', 'git', lambda: 'built-in')
    modules = load_external_plugins(app, d)
    assert modules == [] and app.routes['git'][1]() == 'built-in'


def check_missing_directory_and_non_py_files_are_ignored(root):
    d = make_dir(root, 'site')
    make_plugin(d, 'kcs.py', 'kcs')
    write(os.path.join(d, 'notes.py.deprecated'), 'raise SystemExit\n')
    app = FakeApp()
    load_external_plugins(app, os.pathsep.join([os.path.join(root, 'gone'), d, d]))
    assert list(app.routes) == ['kcs'], app.routes


def main():
    n = 0
    for name, fn in sorted(globals().items()):
        if name.startswith('check_') and callable(fn):
            root = tempfile.mkdtemp()
            try:
                fn(root)
            finally:
                shutil.rmtree(root)
            n += 1
    print('load_plugins: %d checks passed' % n)


if __name__ == '__main__':
    main()
