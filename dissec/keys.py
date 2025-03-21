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
"""Key definitions."""

from __future__ import annotations

import re
from typing import Annotated, Any, ClassVar, TypeVar, Union

from pydantic import StringConstraints
from typing_extensions import TypeAlias

from .utils import Parseable

__all__ = [
    "AppendKey",
    "BasicKey",
    "FieldNameKey",
    "FieldValueKey",
    "Key",
    "SkipKey",
]


BasicKeyT = TypeVar("BasicKeyT", bound="BasicKey")
SkipKeyT = TypeVar("SkipKeyT", bound="SkipKey")
AppendKeyT = TypeVar("AppendKeyT", bound="AppendKey")
FieldNameKeyT = TypeVar("FieldNameKeyT", bound="FieldNameKey")
FieldValueKeyT = TypeVar("FieldValueKeyT", bound="FieldValueKey")


class BasicKey(Parseable):
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
    def parse(
        cls: type[BasicKeyT],
        raw: str,
        /,
    ) -> BasicKeyT:
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


class SkipKey(Parseable):
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
    def parse(
        cls: type[SkipKeyT],
        raw: str,
        /,
    ) -> SkipKeyT:
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


class AppendKey(Parseable):
    """Append key for dissect patterns."""

    __slots__ = ("append_order", "name", "skip_right_padding")

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
    def parse(
        cls: type[AppendKeyT],
        raw: str,
        /,
    ) -> AppendKeyT:
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


class FieldNameKey(Parseable):
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
    def parse(
        cls: type[FieldNameKeyT],
        raw: str,
        /,
    ) -> FieldNameKeyT:
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


class FieldValueKey(Parseable):
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
    def parse(
        cls: type[FieldValueKeyT],
        raw: str,
        /,
    ) -> FieldValueKeyT:
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
