"""
Written by Daniel Sungju Kwon

This provides interface to work with client crash extension
which can be used to do the job 'pykdump extension' cannot do
due to limited libraries.
"""

import os
import sys

from flask import Flask
from flask import jsonify

from load_plugins import load_plugins
from werkzeug.serving import run_simple


to_reload = False

sys.path.append("./support-rules")

def get_app():
    app = Flask(__name__)


    @app.route('/')
    def app_main():
        return 'crash extension helper server'


    @app.route('/list')
    def list_routes():
        result = []
        for rt in app.url_map.iter_rules():
            result.append({
                'methods': list(rt.methods),
                'route': str(rt)
            })
        return jsonify({'routes': result, 'total': len(result)})


    @app.route('/reload')
    def reload():
        global to_reload
        to_reload = True
        return "reloaded"


    return app


class AppReloader(object):
    def __init__(self, create_app):
        self.create_app = create_app
        self.app = create_app()
        load_plugins(self.app)

    def get_application(self):
        global to_reload
        if to_reload:
            self.app = self.create_app()
            load_plugins(self.app)
            to_reload = False

        return self.app

    def __call__(self, environ, start_response):
        app = self.get_application()
        return app(environ, start_response)


application = AppReloader(get_app)


def start_app():
    if "PYCRASHEXT_PORT" in os.environ:
        try:
            run_port = int(os.environ["PYCRASHEXT_PORT"])
        except:
            run_port = 5000
    else:
        run_port = 5000

    run_simple('0.0.0.0', run_port, application,
               use_reloader=True, use_debugger=True, use_evalex=True)


if __name__ == '__main__':
    start_app()
