# Faithful reduction of airflow/api/common/experimental/get_code.py at state X.
# get_code(dag_id) is THE SINK named by advisory TEGRON-PY-AIRFLOW-EXPAPI-0001: it
# reads arbitrary DAG source off disk by fileloc and returns it, with no
# authentication on the experimental-API path that reaches it.
#
# This ENTIRE file is DELETED wholesale at the fix commit (symbol-removal): after the
# fix `get_code` no longer resolves anywhere in the tree.


def get_code(dag_id):
    """Return python code of a given dag_id."""
    return _read_dag_source(dag_id)


def _read_dag_source(fileloc):
    with open(fileloc) as fh:
        return fh.read()
