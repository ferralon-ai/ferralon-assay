# netclient models the (vendored-as-first-party) HTTP client dependency. open_conn is
# THE SINK named by advisory TEGRON-PY-SSRF-0001 (an unvalidated outbound connect =
# SSRF). Every callee is unique by (name, arity) so the source-lexical resolver
# connects each edge soundly: fetch_url -> open_conn -> _dial.
def fetch_url(target):
    return open_conn(target)


def open_conn(url):
    return _dial(url)


def _dial(url):
    return url
