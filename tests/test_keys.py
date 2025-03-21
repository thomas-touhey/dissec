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

from collections.abc import Iterable
from typing import Any

import pytest
from pydantic import TypeAdapter

from dissec.errors import DecodeError
from dissec.keys import (
    AppendKey,
    BasicKey,
    FieldNameKey,
    FieldValueKey,
    Key,
    SkipKey,
)
from dissec.patterns import Pattern


@pytest.mark.parametrize(
    "key,key_repr",
    (
        (BasicKey(name="a"), "BasicKey(name='a')"),
        (
            BasicKey(name="a", skip_right_padding=True),
            "BasicKey(name='a', skip_right_padding=True)",
        ),
        (SkipKey(), "SkipKey()"),
        (SkipKey(name=""), "SkipKey()"),
        (SkipKey(name="a"), "SkipKey(name='a')"),
        (SkipKey(skip_right_padding=True), "SkipKey(skip_right_padding=True)"),
        (
            SkipKey(name="a", skip_right_padding=True),
            "SkipKey(name='a', skip_right_padding=True)",
        ),
        (AppendKey(name="a"), "AppendKey(name='a')"),
        (
            AppendKey(name="a", skip_right_padding=True),
            "AppendKey(name='a', skip_right_padding=True)",
        ),
        (
            AppendKey(name="a", append_order=5),
            "AppendKey(name='a', append_order=5)",
        ),
        (
            AppendKey(name="a", append_order=5, skip_right_padding=True),
            "AppendKey(name='a', append_order=5, skip_right_padding=True)",
        ),
        (FieldNameKey(name="a"), "FieldNameKey(name='a')"),
        (
            FieldNameKey(name="a", skip_right_padding=True),
            "FieldNameKey(name='a', skip_right_padding=True)",
        ),
        (FieldValueKey(name="a"), "FieldValueKey(name='a')"),
        (
            FieldValueKey(name="a", skip_right_padding=True),
            "FieldValueKey(name='a', skip_right_padding=True)",
        ),
    ),
)
def test_key_repr(key: Key, key_repr: str) -> None:
    """Test that the key representation function works."""
    assert repr(key) == key_repr


@pytest.mark.parametrize(
    "key,key_s",
    (
        (SkipKey(), "?"),
        (SkipKey(skip_right_padding=True), "?->"),
        (SkipKey(name="a"), "?a"),
        (SkipKey(name="a", skip_right_padding=True), "?a->"),
        (FieldNameKey(name="a"), "*a"),
        (FieldNameKey(name="a", skip_right_padding=True), "*a->"),
        (FieldValueKey(name="a"), "&a"),
        (FieldValueKey(name="a", skip_right_padding=True), "&a->"),
    ),
)
def test_key_str(key: Key, key_s: str) -> None:
    """Test that the key string conversion function works."""
    assert str(key) == key_s


@pytest.mark.parametrize(
    "key",
    (
        BasicKey(name="a"),
        SkipKey(),
        FieldNameKey(name="b"),
        FieldValueKey(name="c"),
    ),
)
def test_key_hash(key: Key) -> None:
    """Test that key hashing works."""
    assert hash(key) == id(key)


@pytest.mark.parametrize(
    "key,key_sources",
    (
        (BasicKey(name="a"), (BasicKey(name="a"), "a")),
        (BasicKey(name="a", skip_right_padding=True), ("a->",)),
        (SkipKey(), ("?", "", SkipKey(name=""))),
        (AppendKey(name="a"), ("+a", AppendKey(name="a"))),
        (
            AppendKey(name="a", append_order=5),
            ("+a/5", AppendKey(name="a", append_order=5)),
        ),
        (FieldNameKey(name="a"), ("*a", FieldNameKey(name="a"))),
        (FieldValueKey(name="a"), ("&a", FieldValueKey(name="a"))),
    ),
)
def test_validate_key(key: Key, key_sources: Iterable[Any]) -> None:
    """Test that we can pydantic validate into the right value."""
    for src in key_sources:
        assert TypeAdapter(key.__class__).validate_python(src) == key
        assert TypeAdapter(Key).validate_python(src) == key


@pytest.mark.parametrize("raw", ("/", "+", "*", "&", "+?hello"))
def test_parse_key_with_invalid_format(raw: str) -> None:
    """Check if delimiters which require names fail correctly."""
    with pytest.raises(DecodeError, match=r"nvalid key format"):
        x = Pattern.parse_key(raw)
        print(repr(x))
