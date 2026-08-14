# Real, readable first-party module. The vulnerable sink open_conn IS present as a
# first-party def and IS reachable from the Flask route ingress handle_fetch. This
# module indexes and builds a call graph cleanly on its own.
from flask import Flask

app = Flask(__name__)


@app.route('/fetch')
def handle_fetch():
    return fetch_url(1)


def fetch_url(target):
    return open_conn(target)


def open_conn(url):
    return url
