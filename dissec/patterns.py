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

from collections import defaultdict
from collections.abc import Sequence
from itertools import chain, zip_longest
import re
from typing import Annotated, Any, ClassVar, TypeVar, Union

from pydantic import GetCoreSchemaHandler, StringConstraints, TypeAdapter
from pydantic_core.core_schema import (
    CoreSchema,
    ValidationInfo,
    is_instance_schema,
    json_or_python_schema,
    str_schema,
    to_string_ser_schema,
    with_info_after_validator_function,
)
from typing_extensions import TypeAlias

from .errors import DecodeError
from .utils import Runk


PatternType = TypeVar("PatternType", bound="Pattern")
BasicKeyType = TypeVar("BasicKeyType", bound="BasicKey")
SkipKeyType = TypeVar("SkipKeyType", bound="SkipKey")
AppendKeyType = TypeVar("AppendKeyType", bound="AppendKey")
FieldNameKeyType = TypeVar("FieldNameKeyType", bound="FieldNameKey")
FieldValueKeyType = TypeVar("FieldValueKeyType", bound="FieldValueKey")


class BasicKey:
    """Basic key for dissect patterns."""

    __slots__ = ("name", "skip_right_padding")

    _PATTERN: ClassVar[re.Pattern] = re.compile(r"^([^+*&?/]*?)(->)?$")
    """Pattern used to parse the key."""

    name: Annotated[str, StringConstraints(min_length=1)]
    """Name of the key."""

    skip_right_padding: bool
    """Whether to skip right padding."""

    def __init__(
        self,
        /,
        *,
        name: str,
        skip_right_padding: Any = False,
    ) -> None:
        if not name:
            raise ValueError("Name cannot be empty.")

        self.name = name
        self.skip_right_padding = bool(skip_right_padding)

    def __repr__(self, /) -> str:
        rep = f"{self.__class__.__name__}(name={self.name!r}"
        if self.skip_right_padding:
            rep += ", skip_right_padding=True"
        return rep + ")"

    def __str__(self, /) -> str:
        return self.name + ("->" if self.skip_right_padding else "")

    def __hash__(self, /) -> int:
        return hash(id(self))

    def __eq__(self, other: Any, /) -> bool:
        return (
            isinstance(other, BasicKey)
            and other.name == self.name
            and other.skip_right_padding == self.skip_right_padding
        )

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[BasicKeyType],
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
        cls: type[BasicKeyType],
        value: str | BasicKeyType,
        info: ValidationInfo,
        /,
    ) -> BasicKeyType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, cls):
            return value
        else:  # pragma: no cover
            raise NotImplementedError()

    @classmethod
    def parse(
        cls: type[BasicKeyType],
        raw: str,
        /,
    ) -> BasicKeyType:
        """Parse a basic key.

        :param raw: Textual form of the key to parse.
        :return: Pattern.
        :raises ValueError: Could not parse a key.
        """
        match = cls._PATTERN.match(raw)
        if match is None:
            raise ValueError("Invalid format.")

        return cls(
            name=match[1],
            skip_right_padding=match[2],
        )


class SkipKey:
    """Skip key for dissect patterns."""

    __slots__ = ("name", "skip_right_padding")

    _PATTERN: ClassVar[re.Pattern] = re.compile(r"^(?:|\?([^+*&?/]*?))(->)?$")
    """Pattern used to parse the key."""

    name: str
    """Optional name of the skip key."""

    skip_right_padding: bool
    """Whether to skip right padding."""

    def __init__(
        self,
        /,
        *,
        name: str = "",
        skip_right_padding: Any = False,
    ) -> None:
        self.name = name
        self.skip_right_padding = bool(skip_right_padding)

    def __repr__(self, /) -> str:
        rep = f"{self.__class__.__name__}("
        sep = ""
        if self.name != "":
            rep += f"name={self.name!r}"
            sep = ", "
        if self.skip_right_padding:
            rep += f"{sep}skip_right_padding=True"
        return rep + ")"

    def __str__(self, /) -> str:
        return "?" + self.name + ("->" if self.skip_right_padding else "")

    def __hash__(self, /) -> int:
        return hash(id(self))

    def __eq__(self, other: Any, /) -> bool:
        return (
            isinstance(other, SkipKey)
            and other.name == self.name
            and other.skip_right_padding == self.skip_right_padding
        )

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[SkipKeyType],
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
        cls: type[SkipKeyType],
        value: str | SkipKeyType,
        info: ValidationInfo,
        /,
    ) -> SkipKeyType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, cls):
            return value
        else:  # pragma: no cover
            raise NotImplementedError()

    @classmethod
    def parse(
        cls: type[SkipKeyType],
        raw: str,
        /,
    ) -> SkipKeyType:
        """Parse a skip key.

        :param raw: Textual form of the key to parse.
        :return: Pattern.
        :raises ValueError: Could not parse a key.
        """
        match = cls._PATTERN.match(raw)
        if match is None:
            raise ValueError("Invalid format.")

        return cls(
            name=match[1] or "",
            skip_right_padding=match[2],
        )


class AppendKey:
    """Append key for dissect patterns."""

    __slots__ = ("name", "append_order", "skip_right_padding")

    _PATTERN: ClassVar[re.Pattern] = re.compile(
        r"^\+([^+*&?/]*?)(?:/([0-9]+))?(->)?$",
    )
    """Pattern used to parse the key."""

    name: Annotated[str, StringConstraints(min_length=1)]
    """Optional name of the skip key."""

    append_order: int | None
    """The position at which to append the key."""

    skip_right_padding: bool
    """Whether to skip right padding."""

    def __init__(
        self,
        /,
        *,
        name: str,
        append_order: int | None = None,
        skip_right_padding: Any = False,
    ) -> None:
        if not name:
            raise ValueError("Name cannot be empty.")

        self.name = name
        self.append_order = append_order
        self.skip_right_padding = bool(skip_right_padding)

    def __repr__(self, /) -> str:
        rep = f"{self.__class__.__name__}(name={self.name!r}"
        if self.append_order is not None:
            rep += f", append_order={self.append_order!r}"
        if self.skip_right_padding:
            rep += ", skip_right_padding=True"
        return rep + ")"

    def __str__(self, /) -> str:
        return (
            "+"
            + self.name
            + (
                f"/{self.append_order}"
                if self.append_order is not None
                else ""
            )
            + ("->" if self.skip_right_padding else "")
        )

    def __hash__(self, /) -> int:
        return hash(id(self))

    def __eq__(self, other: Any, /) -> bool:
        return (
            isinstance(other, AppendKey)
            and other.name == self.name
            and other.append_order == self.append_order
            and other.skip_right_padding == self.skip_right_padding
        )

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[AppendKeyType],
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
        cls: type[AppendKeyType],
        value: str | AppendKeyType,
        info: ValidationInfo,
        /,
    ) -> AppendKeyType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, cls):
            return value
        else:  # pragma: no cover
            raise NotImplementedError()

    @classmethod
    def parse(
        cls: type[AppendKeyType],
        raw: str,
        /,
    ) -> AppendKeyType:
        """Parse a skip key.

        :param raw: Textual form of the key to parse.
        :return: Pattern.
        :raises ValueError: Could not parse a key.
        """
        match = cls._PATTERN.match(raw)
        if match is None:
            raise ValueError("Invalid format.")

        return cls(
            name=match[1],
            append_order=int(match[2]) if match[2] is not None else None,
            skip_right_padding=match[3],
        )


class FieldNameKey:
    """Field name key for dissect patterns."""

    __slots__ = ("name", "skip_right_padding")

    _PATTERN: ClassVar[re.Pattern] = re.compile(r"^\*([^+*&?/]*?)(->)?$")
    """Pattern used to parse the key."""

    name: Annotated[str, StringConstraints(min_length=1)]
    """Optional name of the skip key."""

    skip_right_padding: bool
    """Whether to skip right padding."""

    def __init__(
        self,
        /,
        *,
        name: str,
        skip_right_padding: Any = False,
    ) -> None:
        if not name:
            raise ValueError("Name cannot be empty.")

        self.name = name
        self.skip_right_padding = bool(skip_right_padding)

    def __repr__(self, /) -> str:
        rep = f"{self.__class__.__name__}(name={self.name!r}"
        if self.skip_right_padding:
            rep += ", skip_right_padding=True"
        return rep + ")"

    def __str__(self, /) -> str:
        return "*" + self.name + ("->" if self.skip_right_padding else "")

    def __hash__(self, /) -> int:
        return hash(id(self))

    def __eq__(self, other: Any, /) -> bool:
        return (
            isinstance(other, FieldNameKey)
            and other.name == self.name
            and other.skip_right_padding == self.skip_right_padding
        )

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[FieldNameKeyType],
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
        cls: type[FieldNameKeyType],
        value: str | FieldNameKeyType,
        info: ValidationInfo,
        /,
    ) -> FieldNameKeyType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, cls):
            return value
        else:  # pragma: no cover
            raise NotImplementedError()

    @classmethod
    def parse(
        cls: type[FieldNameKeyType],
        raw: str,
        /,
    ) -> FieldNameKeyType:
        """Parse a skip key.

        :param raw: Textual form of the key to parse.
        :return: Pattern.
        :raises ValueError: Could not parse a key.
        """
        match = cls._PATTERN.match(raw)
        if match is None:
            raise ValueError("Invalid format.")

        return cls(
            name=match[1],
            skip_right_padding=match[2],
        )


class FieldValueKey:
    """Field value key for dissect patterns."""

    __slots__ = ("name", "skip_right_padding")

    _PATTERN: ClassVar[re.Pattern] = re.compile(r"^&([^+*&?/]*?)(->)?$")
    """Pattern used to parse the key."""

    name: Annotated[str, StringConstraints(min_length=1)]
    """Optional name of the skip key."""

    skip_right_padding: bool
    """Whether to skip right padding."""

    def __init__(
        self,
        /,
        *,
        name: str,
        skip_right_padding: Any = False,
    ) -> None:
        if not name:
            raise ValueError("Name cannot be empty.")

        self.name = name
        self.skip_right_padding = bool(skip_right_padding)

    def __repr__(self, /) -> str:
        rep = f"{self.__class__.__name__}(name={self.name!r}"
        if self.skip_right_padding:
            rep += ", skip_right_padding=True"
        return rep + ")"

    def __str__(self, /) -> str:
        return "&" + self.name + ("->" if self.skip_right_padding else "")

    def __hash__(self, /) -> int:
        return hash(id(self))

    def __eq__(self, other: Any, /) -> bool:
        return (
            isinstance(other, FieldValueKey)
            and other.name == self.name
            and other.skip_right_padding == self.skip_right_padding
        )

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[FieldValueKeyType],
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
        cls: type[FieldValueKeyType],
        value: str | FieldValueKeyType,
        info: ValidationInfo,
        /,
    ) -> FieldValueKeyType:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)
        elif isinstance(value, cls):
            return value
        else:  # pragma: no cover
            raise NotImplementedError()

    @classmethod
    def parse(
        cls: type[FieldValueKeyType],
        raw: str,
        /,
    ) -> FieldValueKeyType:
        """Parse a skip key.

        :param raw: Textual form of the key to parse.
        :return: Pattern.
        :raises ValueError: Could not parse a key.
        """
        match = cls._PATTERN.match(raw)
        if match is None:
            raise ValueError("Invalid format.")

        return cls(
            name=match[1],
            skip_right_padding=match[2],
        )


Key: TypeAlias = Union[
    BasicKey,
    SkipKey,
    AppendKey,
    FieldNameKey,
    FieldValueKey,
]
"""Key type for dissect patterns."""


class Pattern:
    """Dissect pattern.

    For more information, see :ref:`dissect-patterns`.
    """

    __slots__ = (
        "_append_indexes",
        "_append_lengths",
        "_prefix",
        "_pairs",
        "_pattern",
    )

    _KEY_DELIMITER_FIELD_PATTERN: ClassVar[re.Pattern] = re.compile(
        r"%\{([^}]*?)\}",
    )
    """Pattern used to find keys in a pattern."""

    _KEY_TYPE_ADAPTER: ClassVar[TypeAdapter[Key]] = TypeAdapter(Key)
    """Type adapter for decoding a key."""

    _append_indexes: dict[Key, int]
    """Indexes for keys to add to arrays to concatenate at dissection end.

    This can include both append keys and basic keys sharing the name of
    at least one append key. It is guaranteed to be unique and correctly
    ordered depending on the key name.

    If a key is defined here, it must be processed as an array value rather
    than a basic "replacing" value.
    """

    _append_lengths: dict[str, int]
    """Length of arrays obtained from append keys."""

    _prefix: str
    """Prefix."""

    _pairs: tuple[tuple[Key, str], ...]
    """Parsing pairs in order, using."""

    _pattern: re.Pattern | None
    """Compiled pattern to use for extraction."""

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

        # Check that there is exactly one field name for every field value,
        # and exactly one field value for every field name.
        field_names = [
            key.name for key, _ in pairs if isinstance(key, FieldNameKey)
        ]
        field_values = [
            key.name for key, _ in pairs if isinstance(key, FieldValueKey)
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

        # Determine the append keys, and orders in such keys.
        # NOTE: that as long as a key name has at least one append key attached
        # to it, basic keys with the same key name will actually also be
        # append keys, so we actually base ourselves on the names for both
        # append and basic keys.
        # NOTE: The order is just a general idea of the order, and is not
        # unique. Basic keys or append keys with no explicit order are
        # considered to have order -1 (which cannot be specified using the
        # append with order specifier).
        append_key_names: set[str] = {
            key.name for key, _ in pairs if isinstance(key, AppendKey)
        }
        append_keys: defaultdict[
            str,
            defaultdict[int, list[Key]],
        ] = defaultdict(lambda: defaultdict(list))
        append_indexes: dict[Key, int] = {}
        append_lengths: dict[str, int] = {}

        for key, _ in pairs:
            if key.name not in append_key_names:
                continue
            elif isinstance(key, AppendKey):
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

        self._append_indexes = append_indexes
        self._append_lengths = append_lengths
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
        cls: type[PatternType],
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
            elif isinstance(key, FieldNameKey):
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
