# Out-of-range shape (advisory TEGRON-PY-JINJA2-SSTI-0001, affects Jinja2 < 2.11.3).
# The build declares Jinja2==3.1.2 (see requirements.txt), which is provably >= the
# advisory upper bound 2.11.3 under PEP 440 ordering, so the PyPI disqualification
# predicate returns (outside=true, ok=true): version-disqualified, independent of any
# reachability. This module exists only so the repro is a real buildable tree; the arm
# is the pipeline comparator, not the scanner.
from jinja2 import Template


def render(name):
    return Template("Hello {{ name }}").render(name=name)
