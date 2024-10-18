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

from pydantic import BaseModel
import pytest

from dissec.errors import DecodeError
from dissec.patterns import Key, KeyModifier, Pattern


@pytest.mark.parametrize("raw", ("/", "+"))
def test_parse_key_with_missing_name(raw: str) -> None:
    """Check if delimiters which require names fail correctly."""
    with pytest.raises(DecodeError, match=r"key name could not be det"):
        Key.parse(raw)


def test_parse_key_with_multiple_modifiers() -> None:
    """Check that parsing a pattern with multiple modifiers."""
    with pytest.raises(DecodeError, match=r"ultiple modifiers"):
        Key.parse("+?hello")


@pytest.mark.parametrize(
    "raw,prefix,pairs",
    (
        (
            "_%{hello}_+%{+no}sfx",
            "_",
            (
                (Key(name="hello"), "_+"),
                (
                    Key(
                        name="no",
                        modifier=KeyModifier.APPEND,
                    ),
                    "sfx",
                ),
            ),
        ),
        (
            "%{+a->}",
            "",
            (
                (
                    Key(
                        name="a",
                        modifier=KeyModifier.APPEND,
                        skip_right_padding=True,
                    ),
                    "",
                ),
            ),
        ),
        (
            "%{+/a/12}%{?a}x",
            "",
            (
                (
                    Key(
                        name="a",
                        modifier=KeyModifier.APPEND_WITH_ORDER,
                        append_position=12,
                    ),
                    "",
                ),
                (
                    Key(
                        name="a",
                        modifier=KeyModifier.NAMED_SKIP,
                        skip=True,
                    ),
                    "x",
                ),
            ),
        ),
        (
            ": %{&hello}\n=> %{*hello}",
            ": ",
            (
                (
                    Key(name="hello", modifier=KeyModifier.FIELD_VALUE),
                    "\n=> ",
                ),
                (
                    Key(name="hello", modifier=KeyModifier.FIELD_NAME),
                    "",
                ),
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
    assert (pattern.prefix, tuple(pattern.pairs)) == (prefix, tuple(pairs))


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
