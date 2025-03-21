#!/usr/bin/env python
# *****************************************************************************
# Copyright (C) 2024 Thomas Touhey <thomas@touhey.fr>
#
# This software is governed by the CeCILL-C license under French law and
# abiding by the rules of distribution of free software. You can use, modify
# and/or redistribute the software under the terms of the CeCILL-C license
# as circulated by CEA, CNRS and INRIA at the following
# URL: https://cecill.info
#
# As a counterpart to the access to the source code and rights to copy, modify
# and redistribute granted by the license, users are provided only with a
# limited warranty and the software's author, the holder of the economic
# rights, and the successive licensors have only limited liability.
#
# In this respect, the user's attention is drawn to the risks associated with
# loading, using, modifying and/or developing or reproducing the software by
# the user in light of its specific status of free software, that may mean
# that it is complicated to manipulate, and that also therefore means that it
# is reserved for developers and experienced professionals having in-depth
# computer knowledge. Users are therefore encouraged to load and test the
# software's suitability as regards their requirements in conditions enabling
# the security of their systems and/or data to be ensured and, more generally,
# to use and operate it in the same conditions as regards security.
#
# The fact that you are presently reading this means that you have had
# knowledge of the CeCILL-C license and that you accept its terms.
# *****************************************************************************
"""Unit tests for the ``dissec.patterns`` module."""

from __future__ import annotations

from collections.abc import Sequence

import pytest
from pydantic import BaseModel

from dissec.patterns import (
    AppendKey,
    BasicKey,
    FieldNameKey,
    FieldValueKey,
    Key,
    Pattern,
    SkipKey,
)


@pytest.mark.parametrize(
    "raw,prefix,pairs",
    (
        (
            "_%{hello}_+%{+no}sfx",
            "_",
            (
                (BasicKey(name="hello"), "_+"),
                (AppendKey(name="no"), "sfx"),
            ),
        ),
        (
            "%{+a->}",
            "",
            ((AppendKey(name="a", skip_right_padding=True), ""),),
        ),
        (
            "%{+a/12}%{?a}x",
            "",
            (
                (AppendKey(name="a", append_order=12), ""),
                (SkipKey(name="a"), "x"),
            ),
        ),
        (
            ": %{*hello}\n=> %{&hello}",
            ": ",
            (
                (FieldNameKey(name="hello"), "\n=> "),
                (FieldValueKey(name="hello"), ""),
            ),
        ),
    ),
)
def test_parse_pattern(
    raw: str,
    prefix: str,
    pairs: Sequence[tuple[Key, str]],
) -> None:
    """Check that we can parse a pattern."""

    class MyModel(BaseModel):
        pattern: Pattern

    pattern = MyModel(pattern=raw).pattern
    assert pattern.prefix == prefix
    assert tuple(pattern.pairs) == tuple(pairs)


@pytest.mark.parametrize(
    "raw",
    (
        "hello, world",
        "a %{} pattern",
        "a %{->} pattern",
        "a %{?hello} pattern",
    ),
)
def test_parse_pattern_with_no_key(raw: str) -> None:
    """Check that parsing a pattern with no key produces an error."""
    with pytest.raises(
        ValueError,
        match=r"Unable to find any keys or delimiters",
    ):
        Pattern.parse(raw)


@pytest.mark.parametrize(
    "raw",
    (
        # 1 name, no value.
        "%{*a} %{}",
        # 1 value, no name.
        "%{&a} %{}",
        # Multiple names, no value.
        "%{*a} %{*a->} %{}",
        # Multiple values, no name.
        "%{&a->} %{a}",
        # Multiple names, 1 value.
        "%{&a} %{*a->} %{*a}",
        # Multiple values, 1 name.
        "%{&a->} %{*a->} %{&a}",
        # Multiple names, multiple values.
        "%{&a} %{*a} %{&a->} %{*a}",
    ),
)
def test_parse_pattern_with_unmatched_fields(raw: str) -> None:
    """Check if field/value are matched correctly."""
    with pytest.raises(
        ValueError,
        match=r"Found invalid key/reference associations: a.",
    ):
        Pattern.parse(raw)


def test_parse_pattern_obj() -> None:
    """Check that we can coalesce a pattern object."""

    class MyModel(BaseModel):
        pattern: Pattern

    pattern = Pattern.parse("%{a}")
    assert pattern == MyModel(pattern=pattern).pattern
    assert pattern != MyModel(pattern="%{x}").pattern
    assert pattern == "%{a}"
    assert pattern != "%{x}"
    assert pattern != 5


@pytest.mark.parametrize("pattern", ("%{x}", "%{+x->}"))
def test_format_pattern(pattern: str) -> None:
    """Check that the pattern works."""
    assert str(Pattern.parse(pattern)) == pattern


def test_compare_pattern() -> None:
    """Check that comparing the pattern works."""
    p = Pattern.parse("%{?}%{a}")
    assert p == "%{}%{a}"
    assert p == "%{?}%{a}"
    assert p != "%{?/}"


@pytest.mark.parametrize(
    "pattern,raw,expected",
    (
        # Examples from:
        # https://www.elastic.co/guide/en/elasticsearch/reference
        # /current/dissect-processor.html
        (
            '%{clientip} %{ident} %{auth} [%{@timestamp}] "%{verb} '
            + '%{request} HTTP/%{httpversion}" %{status} %{size}',
            '1.2.3.4 - - [30/Apr/1998:22:00:52 +0000] "GET '
            + '/english/venues/cities/images/montpellier/18.gif HTTP/1.0" '
            + "200 3171",
            {
                "request": "/english/venues/cities/images/montpellier/18.gif",
                "auth": "-",
                "ident": "-",
                "verb": "GET",
                "@timestamp": "30/Apr/1998:22:00:52 +0000",
                "size": "3171",
                "clientip": "1.2.3.4",
                "httpversion": "1.0",
                "status": "200",
            },
        ),
        (
            "%{ts->} %{level}",
            "1998-08-10T17:15:42,466          WARN",
            {"ts": "1998-08-10T17:15:42,466", "level": "WARN"},
        ),
        (
            "[%{ts}]%{->}[%{level}]",
            "[1998-08-10T17:15:42,466]            [WARN]",
            {"ts": "1998-08-10T17:15:42,466", "level": "WARN"},
        ),
        (
            "%{+name} %{+name} %{+name} %{+name}",
            "john jacob jingleheimer schmidt",
            {"name": "john jacob jingleheimer schmidt"},
        ),
        (
            "%{+name/2} %{+name/4} %{+name/3} %{+name/1}",
            "john jacob jingleheimer schmidt",
            {"name": "schmidt john jingleheimer jacob"},
        ),
        (
            "%{clientip} %{?ident} %{?auth} [%{@timestamp}]",
            "1.2.3.4 - - [30/Apr/1998:22:00:52 +0000]",
            {
                "clientip": "1.2.3.4",
                "@timestamp": "30/Apr/1998:22:00:52 +0000",
            },
        ),
        (
            "[%{ts}] [%{level}] %{*p1}:%{&p1} %{*p2}:%{&p2}",
            "[2018-08-10T17:15:42,466] [ERR] ip:1.2.3.4 error:REFUSED",
            {
                "ts": "2018-08-10T17:15:42,466",
                "level": "ERR",
                "ip": "1.2.3.4",
                "error": "REFUSED",
            },
        ),
        # Custom examples for testing specific cases.
        (
            # Using both basic and append keys with a same name.
            "%{+hello/2}-%{+hello/0}-%{hello}",
            "abc-def-ghi",
            {"hello": "ghi def abc"},
        ),
        (
            # Using the same name for an append key and field name/value.
            "%{+hello/2}-%{*hello}-%{&hello}",
            "abc-def-ghi",
            {"hello": "abc", "def": "ghi"},
        ),
    ),
)
def test_dissect(pattern: str, raw: str, expected: dict[str, str]) -> None:
    """Check that string dissection using pattern works."""
    assert (
        Pattern.parse(pattern).dissect(raw, append_separator=" ") == expected
    )


def test_dissect_impossible() -> None:
    """Check that parsing with the wrong pattern works correctly."""
    pattern = Pattern.parse("%{hello}-%{world}")
    with pytest.raises(ValueError, match=r"Cannot dissect"):
        pattern.dissect("hello, world!")


def test_multiple_pattern_compile() -> None:
    """Test that the regex for a pattern compiles only once."""
    p = Pattern.parse("%{a}")
    reg = p.pattern
    assert reg is p.pattern
