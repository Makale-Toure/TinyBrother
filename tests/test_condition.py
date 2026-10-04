import pytest

from tinybrother.engine.condition import parse_condition
from tinybrother.engine.errors import UnsupportedRule

NAMES = ["selection", "filter_a", "filter_b", "_hidden"]


SELECTIONS = {n: (lambda f, n=n: f.get(n, False)) for n in NAMES}


def run(cond, **values):
    return parse_condition(cond, SELECTIONS)(values)


def test_simple():
    assert run("selection", selection=True)
    assert not run("selection")


def test_and_or_not_precedence():
    # not binds tighter than and, and tighter than or
    assert run("selection and not filter_a or filter_b", selection=True)
    assert not run("selection and not filter_a", selection=True, filter_a=True)
    assert run("selection and not filter_a or filter_b", filter_b=True)


def test_parentheses():
    assert not run("selection and (filter_a or filter_b)", selection=True)
    assert run("selection and (filter_a or filter_b)", selection=True, filter_b=True)


def test_one_of_and_all_of_patterns():
    assert run("1 of filter_*", filter_b=True)
    assert not run("all of filter_*", filter_b=True)
    assert run("all of filter_*", filter_a=True, filter_b=True)


def test_them_ignores_underscore_names():
    assert run("all of them", selection=True, filter_a=True, filter_b=True)


def test_list_of_conditions_is_or():
    assert run(["filter_a", "selection"], selection=True)


@pytest.mark.parametrize("cond", [
    "selection | count() > 5",
    "unknown",
    "selection and",
    "1 of nothing_*",
    "(selection",
])
def test_invalid_conditions(cond):
    with pytest.raises(UnsupportedRule):
        parse_condition(cond, SELECTIONS)
