# Installed-but-unreachable shape (advisory TEGRON-PY-SSRF-0001). The vulnerable sink
# open_conn is PRESENT as a first-party def (so it resolves and is a call-graph node),
# but no recognized ingress or program root reaches it: the only route handler (health)
# calls harmless, and open_conn is an orphan. This is UNKNOWN (no_known_ingress), never
# a confident "safe". Removing the def would make it ABSENT, a different case that does
# NOT satisfy C3 -- the def must stay present.
from flask import Flask

app = Flask(__name__)


@app.route('/health')
def health():
    return harmless(1)


def harmless(x):
    return x


def open_conn(url):
    return url
