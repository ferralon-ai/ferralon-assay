# Faithful reduction of airflow/www/extensions/init_views.py at state X: the
# init_api_experimental() wiring registers the experimental blueprint under
# /api/experimental. At the fix commit this registration (and the whole
# init_api_experimental arm) is DELETED alongside endpoints.py and get_code.py — the
# path-removal at the registration site. The stable-API wiring remains untouched.

from endpoints import api_experimental


def init_api_experimental(app):
    app.register_blueprint(api_experimental, url_prefix="/api/experimental")


def init_api_connexion(app):
    app.register_blueprint(_stable_api, url_prefix="/api/v1")
