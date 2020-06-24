"""Initialize the flaskr application factory."""
import os
from flask import Flask


def create_app(test_config=None):
    """Create and configure the app."""
    app = Flask(__name__, instance_relative_config=True)
    app.config.from_mapping(SECRET_KEY='dev',
                            DATABASE=os.path.join(app.instance_path,
                                                  'flaskr.sqlite'))

    if test_config is None:
        # Load the instance config, if it exist, when not testing.
        app.config.from_pyfile('config.py', silent=True)

    else:
        # Load the test config if passed in.
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists.
    try:
        os.makedirs(app.instance_path)

    except OSError as e:
        print(e)

    @app.route('/hello')
    def hello():
        """Render a simple hello page."""
        return 'Hello World!'

    from . import db
    db.init_app(app)

    return app
