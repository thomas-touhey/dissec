from __future__ import annotations

from dissec.patterns import Pattern

pattern = Pattern.parse("%{+name/2} %{+name/4} %{+name/3} %{+name/1}")
result = pattern.dissect(
    "john jacob jingleheimer schmidt",
    append_separator=", ",
)
print(result)
