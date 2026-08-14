"""Symbol-profile reference fixture (PLAN-070 C1/C2).

One offline, parseable module exercising all eight §4.3 declaration categories in
their Python spelling, so the first-party lexical scanner (IndexSymbols) emits a
representative symbol set to drive the canonical golden profile against. No target
code is executed; the scanner reads this source only.

The categories, in order:
  1. packages/modules      -- this module clause (import path "mod")
  2. types                 -- class Widget
  3. functions             -- module-level build
  4. methods               -- Widget.render
  5. constructors          -- Widget.__init__
  6. overloads/generics    -- typed_get (@overload arms + generic TypeVar)
  7. nested declarations   -- Widget.Config (class nested in a class)
  8. generated symbols     -- traced (a functools.wraps wrapper: a synthesized
                              symbol lexically indistinguishable from its target)
"""

import functools
from typing import overload, TypeVar

T = TypeVar("T")


def build(name):
    """Module-level function (category: functions)."""
    return Widget(name)


class Widget:
    """Exported class (category: types)."""

    class Config:
        """Class nested under Widget (category: nested declarations)."""

        def __init__(self, verbose):
            self.verbose = verbose

    def __init__(self, name):
        """Constructor (category: constructors)."""
        self.name = name

    def render(self):
        """Method on Widget (category: methods)."""
        return self.name


@overload
def typed_get(key: str) -> str: ...
@overload
def typed_get(key: int) -> int: ...
def typed_get(key):
    """Overloaded / generic accessor (category: overloads/generics).

    Two @overload signature arms plus a TypeVar-parameterized target; the lexical
    scanner disambiguates same-named declarations by arity only, carrying no
    signature/type-argument descriptor.
    """
    return key


def _tracing(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        return fn(*args, **kwargs)

    return wrapper


@_tracing
def traced(payload):
    """A functools.wraps wrapper (category: generated symbols).

    functools.wraps copies traced's identity onto the synthesized `wrapper`, so the
    two are lexically indistinguishable; a conformant producer must mark the emitted
    symbol Generated, which the current scanner cannot.
    """
    return payload
