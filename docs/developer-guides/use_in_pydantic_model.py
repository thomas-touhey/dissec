from __future__ import annotations

from pydantic import BaseModel

from dissec.patterns import Pattern


class MyModel(BaseModel):
    """My model including a pattern."""

    my_pattern: Pattern
    """Pattern included with the model."""


obj = MyModel(my_pattern="%{hello} - %{world}")
print(obj.model_dump_json())
