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

from collections.abc import Sequence
from enum import IntFlag, auto
from itertools import zip_longest
import re
from typing import Any, ClassVar, TypeVar

from pydantic import BaseModel, ConfigDict, GetCoreSchemaHandler
from pydantic_core.core_schema import (
    CoreSchema,
    ValidationInfo,
    is_instance_schema,
    json_or_python_schema,
    str_schema,
    to_string_ser_schema,
    with_info_after_validator_function,
)

from .errors import DecodeError
from .utils import Runk


PatternType = TypeVar("PatternType", bound="Pattern")
KeyType = TypeVar("KeyType", bound="Key")

_APPEND_WITH_ORDER_PATTERN = re.compile(r"/([0-9]+)$")
_KEY_DELIMITER_FIELD_PATTERN = re.compile(r"%\{([^}]*)\}")


class KeyModifier(IntFlag):
    """Modifier for dissect pattern keys."""

    NONE = 0
    APPEND_WITH_ORDER = auto()
    APPEND = auto()
    FIELD_NAME = auto()
    FIELD_VALUE = auto()
    NAMED_SKIP = auto()


class Key(BaseModel):
    """Key for dissect patterns."""

    _DISSECT_KEY_MODIFIERS: ClassVar[dict[str, KeyModifier]] = {
        "/": KeyModifier.APPEND_WITH_ORDER,
        "+": KeyModifier.APPEND,
        "*": KeyModifier.FIELD_NAME,
        "&": KeyModifier.FIELD_VALUE,
        "?": KeyModifier.NAMED_SKIP,
    }
    """Dissect key modifier values by character."""

    _DISSECT_KEY_MODIFIER_CHARACTERS: ClassVar[dict[KeyModifier, str]] = {
        value: key for key, value in _DISSECT_KEY_MODIFIERS.items()
    }
    """Dissect key modifier characters by value."""

    model_config = ConfigDict(extra="forbid")
    """Model configuration."""

    name: str = ""
    """Name of the dissect key."""

    modifier: KeyModifier = KeyModifier.NONE
    """Modifier."""

    skip: bool = False
    """Whether to skip."""

    skip_right_padding: bool = False
    """Whether to skip right padding."""

    append_position: int = 0
    """Whether to append the position."""

    def __str__(self, /) -> str:
        fmt = "%{"
        if self.modifier != KeyModifier.NONE:
            fmt += self._DISSECT_KEY_MODIFIER_CHARACTERS[self.modifier]

        fmt += self.name
        if self.skip_right_padding:
            fmt += "->"

        return fmt + "}"

    @classmethod
    def parse(
        cls: type[KeyType],
        raw: str,
        /,
        *,
        runk: Runk | None = None,
    ) -> KeyType:
        """Parse a key for a dissect pattern.

        :param raw: Raw dissect key.
        :param runk: Runk instance.
        :return: Dissect key.
        """
        if runk is None:
            runk = Runk()

        skip = not raw
        append_position = 0

        # Read the modifiers and remove them from the beginning of the string.
        # There can be either 0 or 1 operators, or "+/".
        modifier = KeyModifier.NONE
        while raw[:1] in cls._DISSECT_KEY_MODIFIERS:
            prior_modifier = modifier
            modifier = cls._DISSECT_KEY_MODIFIERS[raw[:1]]
            raw = raw[1:]

            if prior_modifier == KeyModifier.NONE:
                continue
            elif (
                modifier == KeyModifier.APPEND_WITH_ORDER
                and prior_modifier == KeyModifier.APPEND
            ):
                continue

            raise DecodeError(
                "Multiple modifiers are not allowed.",
                line=runk.line,
                column=runk.column,
                offset=runk.offset,
            )

        # All modifiers allow having a "->" at the end to skip right padding.
        if raw[-2:] == "->":
            name = raw[:-2]
            skip_right_padding = True
        else:
            name = raw
            skip_right_padding = False

        if modifier == KeyModifier.NONE:
            skip = not name
        elif modifier == KeyModifier.NAMED_SKIP:
            skip = True
        elif modifier == KeyModifier.APPEND_WITH_ORDER:
            while True:
                match = _APPEND_WITH_ORDER_PATTERN.search(name)
                if match is None:
                    break

                append_position = int(match[1])
                name = name[: match.start()]
        elif modifier not in (  # pragma: no cover
            KeyModifier.APPEND,
            KeyModifier.FIELD_NAME,
            KeyModifier.FIELD_VALUE,
        ):
            raise NotImplementedError()

        if not name and not skip:
            raise DecodeError(
                "Key name could not be determined.",
                line=runk.line,
                column=runk.column,
                offset=runk.offset,
            )

        return cls(
            name=name,
            modifier=modifier,
            skip=skip,
            skip_right_padding=skip_right_padding,
            append_position=append_position,
        )


class Pattern:
    """Dissect pattern.

    For more information, see :ref:`dissect-patterns`.
    """

    __slots__ = ("_prefix", "_pairs")

    _prefix: str
    """Prefix."""

    _pairs: tuple[tuple[Key, str], ...]
    """Parsing pairs in order, using."""

    def __init__(
        self,
        /,
        *,
        prefix: str = "",
        pairs: Sequence[tuple[Key, str]] = (),
    ) -> None:
        # Check that at least one key is defined.
        if all(not key.name or key.skip for key, _ in pairs):
            raise ValueError("Unable to find any keys or delimiters.")

        # Check that there is exactly one field name for every field value,
        # and exactly one field value for every field name.
        field_names = [
            key.name
            for key, _ in pairs
            if key.modifier == KeyModifier.FIELD_NAME
        ]
        field_values = [
            key.name
            for key, _ in pairs
            if key.modifier == KeyModifier.FIELD_VALUE
        ]
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

        self._prefix = prefix
        self._pairs = tuple(pairs)

    def __str__(self, /) -> str:
        return self._prefix + "".join(
            f"{key}{sep}" for key, sep in self._pairs
        )

    def __eq__(self, other: Any, /) -> bool:
        if isinstance(other, str):
            return str(self) == other
        if not isinstance(other, Pattern):
            return False

        return self._prefix == other._prefix and self._pairs == other._pairs

    @classmethod
    def parse(
        cls: type[PatternType],
        raw: str,
        /,
        *,
        runk: Runk | None = None,
    ) -> PatternType:
        """Parse a pattern.

        :param raw: Textual form of the pattern to parse.
        :param runk: Runk instance to start from.
        :return: Pattern.
        """
        if runk is None:
            runk = Runk()

        matches: list[re.Match] = list(
            _KEY_DELIMITER_FIELD_PATTERN.finditer(raw),
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

                key = Key.parse(fst[1], runk=runk)
                if snd is not None:
                    delim = raw[fst.end() : snd.start()]
                    runk.count(raw[fst.start() : snd.start()])
                else:
                    delim = raw[fst.end() :]
                    runk.count(raw[fst.start() :])

                pairs.append((key, delim))

        return cls(prefix=prefix, pairs=pairs)

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[PatternType],
        source: type[Any],
        handler: GetCoreSchemaHandler,
    ) -> CoreSchema:
        """Get the pydantic core schema.

        This allows the dissect pattern type to be handled
        within pydantic classes, and imported/exported in JSON schemas.
        """
        return with_info_after_validator_function(
            cls._validate,
            json_or_python_schema(
                json_schema=str_schema(),
                python_schema=is_instance_schema((cls, str)),
                serialization=to_string_ser_schema(),
            ),
        )

    @classmethod
    def _validate(
        cls: type[PatternType],
        value: str | PatternType,
        info: ValidationInfo,
        /,
    ) -> PatternType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, Pattern):
            return cls(prefix=value.prefix, pairs=value.pairs)
        else:  # pragma: no cover
            raise NotImplementedError()

    @property
    def prefix(self, /) -> str:
        """Prefix, i.e. chunk of text that must be ignored at the start."""
        return self._prefix

    @property
    def pairs(self, /) -> Sequence[tuple[Key, str]]:
        """Key / delimiter pairs to use to parse the string."""
        return self._pairs
