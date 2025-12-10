from __future__ import annotations

from dissec.patterns import Pattern

pattern = Pattern.parse("[%{ts}] [%{level}] %{*p1}:%{&p1} %{*p2}:%{&p2}")
result = pattern.dissect(
    "[2018-08-10T17:15:42,466] [ERR] ip:1.2.3.4 error:REFUSED",
)
print(result)
