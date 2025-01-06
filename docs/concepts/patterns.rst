.. _dissect-patterns:

Dissect patterns
================

.. py:currentmodule:: dissec.patterns

Dissect patterns in dissec are equivalent to those defined in
Elasticsearch_\ 's `Dissect processor`_. They can be used to extract
information from strings.

The implementation of such patterns in dissec are inspired from
`DissectParser.java`_ and `DissectKey.java`_, the reference implementation
within Elasticsearch.

Patterns are implemented using the :py:class:`Pattern` class.

Keys and delimiters
-------------------

Dissect patterns are composed of keys, delimited using ``%{...}``, with
separators between keys in order for the dissection to know when a string
matched by a key stops and another starts. A basic example is the following
pattern:

.. code-block:: text

    prefix,%{fst},intermediate,%{snd},final

This pattern codifies two keys, one called ``fst`` and one called ``snd``.
The string is assumed to start with ``prefix,`` and to end with ``,final``,
and both fields are separated by ``,intermediate,``. This pattern can be
used to dissect the following string:

.. code-block:: text

    prefix,first,intermediate,second,final

Where the extracted data will be ``{"fst": "first", "snd": "second"}``.

In Dissec, the pattern is represented with a prefix, and pairs, representing
details regarding a key and the delimiter right after. In the example
provided above:

- The prefix is ``prefix,``;
- The first pair is composed of the ``%{fst}`` key, and the ``,intermediate,``
  delimiter;
- The second and last pair is composed of the ``%{snd}`` key, and the
  ``,final`` delimiter.

.. warning::

    For consistency with Elasticsearch, dissect patterns in dissec require
    at least one non-skip key.

Right padding
~~~~~~~~~~~~~

In general, what is outside the key defines how the string is extracted,
and what is inside the key defines what to do with the string. There is one
exception to this, being the "skip right padding" option, represented by
having ``->`` at the end of the key's contents, e.g. ``%{a->}``.

When a "skip right padding" option is present, the delimiter on the right of
the key can be repeated any non-zero number of times, and none of these
repetitions will be included in the matched string.

The most common example of this is with spaces, e.g.::

    %{hello->} %{world}

In this case, both keys being present are separated by any non-zero repetitions
of a single-space, i.e. ``a    b`` will be dissected successfully into
``{"hello": "a", "world": "b"}``.

A less trivial example of this option can be with any other string, e.g.
``,,`` with the pattern ``%{hello->},,%{world}``. Using this pattern:

* ``a,,b`` will be dissected into ``{"hello": "a", "world": "b"}``;
* ``a,,,,b`` will be dissected into the same result;
* ``a,,,b`` (*note the odd number of commas*) will be dissected into
  ``{"hello": "a", "world": ",b"}``.

Key types
---------

With the exception of right padding, the contents of the keys describe what
to do with the matched string, and how it will interact with other keys to
obtain a dissected string.

This section describes these key types, and how they are represented in
dissect patterns.

A key in general can be represented by the union type :py:class:`Key`.

Basic keys
~~~~~~~~~~

By default, a key with a given name will be extracted into a field with the
given name. For example, the string matched by a ``%{hello}`` key will be
stored into the ``hello`` field in the dissection result.

If there are multiple instances of the same key in a given pattern, e.g.
``%{hello}, %{hello}``, only the string corresponding to the latest occurrence
will be kept. For example, dissecting ``first, second`` with this pattern
will result in ``{"hello": "second"}``.

Basic keys are represented using :py:class:`BasicKey`.

Append keys
~~~~~~~~~~~

In order to not have later fields with the same key replace previous ones as
with basic keys, but concatenate, you can use append keys with one of the
following formats:

* ``%{+your_name_here/your_order_here}``, e.g. ``%{+hello/2}``, or
  ``%{+your_name_here/your_order_here->}`` with right padding skip, with the
  order being an integer equal or greater than zero;
* ``%{+your_name_here}``, or ``%{+your_name_here->}`` with right padding skip,
  with the order being inferior to explicitely provided orders
  (*you can consider it equal to -1 in this case*).

.. note::

    It is possible for basic and append keys to use the same key name;
    in this case, basic keys with this name will be considered append keys
    with no order explicitely given.

    For example, ``%{+hello/2},%{hello}`` and ``%{+hello/2},%{+hello}``
    are equivalent.

In this case, all strings matched by the corresponding append keys will be
concatenated, by order first, then order of appearence in the pattern.
For example, given the following pattern::

    %{+hello},%{+hello/2},%{+hello/0},%{+hello},%{+hello/2},%{+world}

If used to dissect the string ``a,b,c,d,e,f``, the result will be the
following::

    {"hello": "adcbe", "world": "f"}

Since, for the ``hello`` key:

* First, the implicit orders (-1) are concatenated in order of appearence
  in the pattern/string, here ``a`` then ``d``;
* Then, all matched strings of order 0 are added, here ``c``;
* Then, all matched strings of order 2 are added in order of appearence
  in the pattern/string, here ``b`` then ``e``.

By default, when concatenated, the separator is an empty string. However, it
is possible to set one by using the ``append_separator`` keyword parameter
to :py:meth:`Pattern.dissect`.

Append keys are represented using :py:class:`AppendKey`.

Reference keys
~~~~~~~~~~~~~~

Basic and append keys use the name of the key in the pattern to store the
result of their operations in the dissection result. However one may want to
take the name of the field in the dissection result from the dissected string
instead. Reference keys use this principle, while using key names to reconcile
the field name on one side and value on the other.

A field name key is represented by prefixing the key name with ``*``, and a
field value key is represented by prefixing the key name with ``&``. The key
name must be the same between both keys, every name must have a corresponding
value, and every value must have a corresponding name.

For example, a basic use case is the following::

    %{*hello}=%{&hello}

Both keys use the ``hello`` key name, which allows the pattern to understand
both are linked. It is possible to have multiple name/value pairs in a single
pattern::

    %{*hello}=%{&hello} %{*world}=%{&world}

Also note that it is not required to have the keys in a specific order, or
to have them next to each other in any way, you can move them around in the
pattern as long as you keep the same key name. For example::

    Value is %{&hello} in context %{context} for key %{*hello}.

By matching this pattern with the following message::

    Value is very good in context default for key status.

You obtain the following dissection result::

    {"context": "default", "status": "very good"}

Field name keys are represented using :py:class:`FieldNameKey`, and field
values keys are represented using :py:class:`FieldValueKey`.

Skip keys
~~~~~~~~~

In order to skip a string that does not have a fixed format, it is possible
to have one of the following:

* An unnamed skip, using either ``%{}`` or ``%{?}``, or if skipping right
  padding, using either ``%{->}`` or ``%{?->}``;
* A named skip, by using ``%{?your_skip_name_here}`` or, if skipping right
  padding, ``%{?your_skip_name_here->}``.

In either case, the string matched by such a key will not be included in the
dissection result, and only be discarded.

Skip keys are represented using :py:class:`SkipKey`.

.. _Elasticsearch: https://www.elastic.co/elasticsearch
.. _Dissect processor:
    https://www.elastic.co/guide/en/elasticsearch/reference/current/
    dissect-processor.html
.. _DissectParser.java:
    https://github.com/elastic/elasticsearch/blob/main/libs/dissect/
    src/main/java/org/elasticsearch/dissect/DissectParser.java
.. _DissectKey.java:
    https://github.com/elastic/elasticsearch/blob/main/libs/dissect/
    src/main/java/org/elasticsearch/dissect/DissectKey.java
