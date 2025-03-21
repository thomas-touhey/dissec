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
"""General utilities."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, TypeVar

from pydantic import BaseModel, GetCoreSchemaHandler
from pydantic_core.core_schema import (
    CoreSchema,
    ValidationInfo,
    is_instance_schema,
    json_or_python_schema,
    str_schema,
    to_string_ser_schema,
    with_info_after_validator_function,
)

ParseableT = TypeVar("ParseableT", bound="Parseable")


class Parseable(ABC):
    """Class with a string representation, which can be parsed."""

    @classmethod
    @abstractmethod
    def parse(
        cls: type[ParseableT],
        raw: str,
        /,
    ) -> ParseableT:
        """Parse the string representation into an object."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls: type[ParseableT],
        _source: type[Any],
        _handler: GetCoreSchemaHandler,
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
        cls: type[ParseableT],
        value: str | ParseableT,
        _info: ValidationInfo,
        /,
    ) -> ParseableT:
        """Validate a pydantic value.

        :param value: Value to validate.
        :param info: Validation information, if required.
        :return: Obtained pattern.
        """
        if isinstance(value, str):
            return cls.parse(value)

        if isinstance(value, cls):
            return value

        raise NotImplementedError()  # pragma: no cover


class Runk(BaseModel):
    """Ronald's universal number kounter.

    This counts lines, columns and offsets.
    """

    line: int = 1
    """Line number, counting from 1."""

    column: int = 1
    """Column number, counting from 1."""

    offset: int = 0
    """Offset in the string, counting from 0."""

    def count(self, raw: str, /) -> None:
        """Add a string to the count.

        :param raw: Raw string to take into account.
        """
        self.offset += len(raw)
        try:
            newline_offset = raw.rindex("\n")
        except ValueError:
            self.column += len(raw)
        else:
            self.line += raw.count("\n")
            self.column = len(raw) - newline_offset
