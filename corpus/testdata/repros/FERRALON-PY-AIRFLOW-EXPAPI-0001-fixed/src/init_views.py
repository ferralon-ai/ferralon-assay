# Faithful reduction of airflow/www/extensions/init_views.py at state Y — the
# "Delete experimental API" fix (apache/airflow PR #41434, Airflow 3.0.0). At the fix
# commit endpoints.py and get_code.py are DELETED wholesale, and init_api_experimental
# (the experimental-blueprint registration wiring) is removed with them. Only the
# stable-API wiring remains: there is no @api_experimental.route ingress and no
# get_code sink anywhere in the tree.
#
# The ingress -> sink path is doubly gone: symbol-removal (get_code no longer resolves)
# AND path-removal (the route decorator + blueprint registration are deleted). Either
# alone flips reachable_candidate -> not_exploitable.


def init_api_connexion(app):
    app.register_blueprint(_stable_api, url_prefix="/api/v1")
