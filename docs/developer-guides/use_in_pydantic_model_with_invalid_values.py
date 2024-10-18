from __future__ import annotations

from pydantic import BaseModel

from dissec.patterns import Pattern


class MyModel(BaseModel):
    """My model including a pattern."""

    fst: Pattern
    snd: Pattern
    thd: Pattern


MyModel(fst="hello, world", snd="%{*my_field}", thd="%{+}")
