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
"""Pattern definitions."""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Iterable, Mapping, Sequence
from itertools import chain, zip_longest
from typing import Any, ClassVar, TypeVar

from pydantic import TypeAdapter

from .errors import DecodeError
from .keys import (
    AppendKey,
    BasicKey,
    FieldNameKey,
    FieldValueKey,
    Key,
    SkipKey,
)
from .utils import Parseable, Runk

__all__ = ["Pattern"]


PatternT = TypeVar("PatternT", bound="Pattern")


class Pattern(Parseable):
    """Dissect pattern.

    For more information, see :ref:`dissect-patterns`.
    """

    __slots__ = (
        "_append_indexes",
        "_append_lengths",
        "_pairs",
        "_pattern",
        "_prefix",
    )

    _KEY_DELIMITER_FIELD_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"%\{([^}]*?)\}",
    )
    """Pattern used to find keys in a pattern."""

    _KEY_TYPE_ADAPTER: ClassVar[TypeAdapter[Key]] = TypeAdapter(Key)
    """Type adapter for decoding a key."""

    _append_indexes: Mapping[Key, int]
    """Indexes for keys to add to arrays to concatenate at dissection end.

    This can include both append keys and basic keys sharing the name of
    at least one append key. It is guaranteed to be unique and correctly
    ordered depending on the key name.

    If a key is defined here, it must be processed as an array value rather
    than a basic "replacing" value.
    """

    _append_lengths: Mapping[str, int]
    """Length of arrays obtained from append keys."""

    _prefix: str
    """Prefix."""

    _pairs: tuple[tuple[Key, str], ...]
    """Parsing pairs in order, using."""

    _pattern: re.Pattern | None
    """Compiled pattern to use for extraction."""

    @staticmethod
    def check_name_value_keys(keys: Iterable[Key], /) -> None:
        """Check that name/value keys are defined correctly in an iterable.

        This method checks that there is exactly one field name for every
        field value, and exactly one field value for every field name.

        :raises ValueError: The constraint is not respected.
        """
        field_names: list[str] = []
        field_values: list[str] = []

        for key in keys:
            if isinstance(key, FieldNameKey):
                field_names.append(key.name)
            elif isinstance(key, FieldValueKey):
                field_values.append(key.name)

        invalid_keys = [
            key
            for key in set(field_names).union(field_values)
            if field_names.count(key) != 1 or field_values.count(key) != 1
        ]
        if invalid_keys:
            raise ValueError(
                "Found invalid key/reference associations: "
                + ", ".join(invalid_keys)
                + ". Please ensure each '*<key>' is matched with a "
                + "matching '&<key>'.",
            )

    @staticmethod
    def determine_append_key_lengths_and_orders(
        keys: Iterable[Key],
        /,
    ) -> tuple[Mapping[str, int], Mapping[Key, int]]:
        """Determine the append keys, and orders in such keys.

        .. note::

            As long as a key name has at least one append key attached to it,
            basic keys with the same key name will actually also be append
            keys, so we actually base ourselves on the names for both
            append and basic keys.

        .. note::

            The order is just a general idea of the order, and is not unique.
            Basic keys or append keys with no explicit order are considered
            to have order -1 (which cannot be specified using the append
            with order specifier).

        :return: A tuple presenting key name to length mapping, and key to
            order mapping.
        """
        key_list = tuple(keys)

        append_key_names: set[str] = {
            key.name for key in key_list if isinstance(key, AppendKey)
        }
        append_keys: defaultdict[
            str,
            defaultdict[int, list[Key]],
        ] = defaultdict(lambda: defaultdict(list))
        append_indexes: dict[Key, int] = {}
        append_lengths: dict[str, int] = {}

        for key in key_list:
            if key.name not in append_key_names:
                continue

            if isinstance(key, AppendKey):
                append_order = key.append_order
            elif isinstance(key, BasicKey):
                append_order = None
            else:  # pragma: no cover
                continue

            append_keys[key.name][
                append_order if append_order is not None else -1
            ].append(key)

        for key_name, keys_grouped_by_order in append_keys.items():
            last_index = 0
            for index, key in enumerate(
                chain(
                    *(
                        values
                        for _, values in sorted(keys_grouped_by_order.items())
                    ),
                ),
            ):
                append_indexes[key] = index
                last_index = index

            append_lengths[key_name] = last_index + 1

        return append_lengths, append_indexes

    def __init__(
        self,
        /,
        *,
        prefix: str = "",
        pairs: Sequence[tuple[Key, str]] = (),
    ) -> None:
        # Check that at least one key is defined.
        if all(not key.name or isinstance(key, SkipKey) for key, _ in pairs):
            raise ValueError("Unable to find any keys or delimiters.")

        self.check_name_value_keys(key for key, _ in pairs)

        (
            self._append_lengths,
            self._append_indexes,
        ) = self.determine_append_key_lengths_and_orders(
            key for key, _ in pairs
        )
        self._prefix = prefix
        self._pairs = tuple(pairs)
        self._pattern = None

    def __str__(self, /) -> str:
        return self._prefix + "".join(
            f"%{{{key}}}{sep}" for key, sep in self._pairs
        )

    def __eq__(self, other: Any, /) -> bool:
        if isinstance(other, str):
            try:
                pattern = self.parse(other)
            except ValueError:
                return False
        elif isinstance(other, Pattern):
            pattern = other
        else:
            return False

        return (
            self._prefix == pattern._prefix and self._pairs == pattern._pairs
        )

    @classmethod
    def parse_key(
        cls: type[PatternT],
        raw: str,
        /,
        *,
        runk: Runk | None = None,
    ) -> Key:
        """Parse a key for a dissect pattern.

        :param raw: Raw dissect key.
        :param runk: Runk instance.
        :return: Dissect key.
        """
        if runk is None:
            runk = Runk()

        try:
            return cls._KEY_TYPE_ADAPTER.validate_python(raw)
        except ValueError as exc:
            raise DecodeError(
                "Invalid key format.",
                line=runk.line,
                column=runk.column,
                offset=runk.offset,
            ) from exc

    @classmethod
    def parse(
        cls: type[PatternT],
        raw: str,
        /,
        *,
        runk: Runk | None = None,
    ) -> PatternT:
        """Parse a pattern.

        :param raw: Textual form of the pattern to parse.
        :param runk: Runk instance to start from.
        :return: Pattern.
        """
        if runk is None:
            runk = Runk()

        matches: list[re.Match] = list(
            cls._KEY_DELIMITER_FIELD_PATTERN.finditer(raw),
        )
        if not matches:
            prefix: str = raw
            pairs: list[tuple[Key, str]] = []
        else:
            prefix = raw[: matches[0].start()]
            pairs = []

            runk.count(prefix)
            for fst, snd in zip_longest(matches, matches[1:], fillvalue=None):
                if fst is None:  # pragma: no cover
                    continue

                key = cls.parse_key(fst[1], runk=runk)
                if snd is not None:
                    delim = raw[fst.end() : snd.start()]
                    runk.count(raw[fst.start() : snd.start()])
                else:
                    delim = raw[fst.end() :]
                    runk.count(raw[fst.start() :])

                pairs.append((key, delim))

        return cls(prefix=prefix, pairs=pairs)

    @property
    def prefix(self, /) -> str:
        """Prefix, i.e. chunk of text that must be ignored at the start."""
        return self._prefix

    @property
    def pairs(self, /) -> Sequence[tuple[Key, str]]:
        """Key / delimiter pairs to use to parse the string."""
        return self._pairs

    @property
    def pattern(self, /) -> re.Pattern:
        """Pattern."""
        if self._pattern is not None:
            return self._pattern

        pattern = re.compile(
            r"^"
            + re.escape(self._prefix)
            + r"".join(
                r"(.*?)"
                + (
                    rf"(?:{re.escape(delim)})+"
                    if key.skip_right_padding
                    else re.escape(delim)
                )
                for key, delim in self._pairs
            )
            + r"$",
        )

        self._pattern = pattern
        return pattern

    def dissect(
        self,
        raw: str,
        /,
        *,
        append_separator: str = "",
    ) -> dict[str, str]:
        """Use the pattern to dissect a string.

        :param raw: Raw string to dissect.
        :param append_separator: Separator to use with append fields.
        :return: Extracted data.
        :raises ValueError: Raw string dissection was not possible.
        """
        match = self.pattern.fullmatch(raw)
        if match is None:
            raise ValueError("Cannot dissect the provided string.")

        result: dict[str, str] = {}
        arrays: dict[str, list[str]] = {
            key: ["" for _ in range(length)]
            for key, length in self._append_lengths.items()
        }
        field_names: dict[str, str] = {}
        field_values: dict[str, str] = {}

        for (key, _), group in zip(self._pairs, match.groups()):
            if isinstance(key, SkipKey):
                continue

            if isinstance(key, FieldNameKey):
                field_names[key.name] = group
            elif isinstance(key, FieldValueKey):
                field_values[key.name] = group
            else:
                try:
                    index = self._append_indexes[key]
                except KeyError:
                    result[key.name] = group
                else:
                    arrays[key.name][index] = group

        result.update(
            {
                key: append_separator.join(values)
                for key, values in arrays.items()
            },
        )
        result.update(
            {
                key[1]: value[1]
                for key, value in zip(
                    sorted(field_names.items()),
                    sorted(field_values.items()),
                )
            },
        )
        return result
