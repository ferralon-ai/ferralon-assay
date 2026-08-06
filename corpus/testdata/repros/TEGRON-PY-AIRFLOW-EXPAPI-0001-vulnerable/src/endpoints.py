# Faithful reduction of airflow/www/api/experimental/endpoints.py at state X — the
# parent of the "Delete experimental API" removal (apache/airflow PR #41434, shipped
# in Airflow 3.0.0). The experimental REST API registers its handlers with Flask
# Blueprint route decorators applied DIRECTLY on the handler def (not add_url_rule,
# not a registration table), so the analyzer sees the decorator call-leaf `.route`
# and marks the following def as an http_route ingress.
#
# get_dag_code is the ingress: it forwards its dag_id straight into the get_code sink
# (a direct named call), so the source call graph is ingress(get_dag_code) -> get_code.
# The experimental API has NO access control by default (CVE-2020-13927 family), so
# this route reaches the arbitrary-DAG-source-read sink unauthenticated.
#
# This ENTIRE module is DELETED at the fix commit (path-removal + the handler that
# reaches the sink is gone).

from flask import Blueprint

from get_code import get_code

api_experimental = Blueprint("api_experimental", __name__)


@api_experimental.route("/dags/<string:dag_id>/code", methods=["GET"])
@requires_authentication
def get_dag_code(dag_id):
    """Return python code of a given dag_id (ingress -> sink, direct named call)."""
    return get_code(dag_id)
