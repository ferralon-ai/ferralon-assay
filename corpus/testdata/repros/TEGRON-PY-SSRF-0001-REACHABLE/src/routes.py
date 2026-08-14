# Reachable shape (advisory TEGRON-PY-SSRF-0001): a Flask route decorator applied
# directly on the handler def marks proxy_view as an http_route ingress. The handler
# forwards into the netclient helper, which reaches the vulnerable sink open_conn.
# The ingress->sink path is proxy_view -> fetch_url -> open_conn (multi-hop, and
# crossing the module boundary into netclient). See F-B1: the sink is vendored as
# FIRST-PARTY source, so "transitive" is a property of this fixture's advisory/manifest
# metadata, not something the current scanner observes.
from flask import Flask

from netclient import fetch_url

app = Flask(__name__)


@app.route('/proxy')
def proxy_view():
    return fetch_url(1)
