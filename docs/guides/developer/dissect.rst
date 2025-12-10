Dissecting a string using dissect patterns
==========================================

.. py:currentmodule:: dissec.patterns

You can actually dissect a string using a pattern by:

1. Parsing the pattern using :py:meth:`Pattern.parse`;
2. Using the pattern to dissect the string using :py:meth:`Pattern.dissect`.

A complete example is the following:

.. literalinclude:: dissect.py

This script displays the following in the console:

.. literalinclude:: dissect_result.txt
    :language: text

Using an append separator
-------------------------

If you are using append or append with order keys, you can optionally set
the ``append_separator`` keyword on :py:meth:`Pattern.dissect`.
For example:

.. literalinclude:: dissect_with_separator.py

This script displays the following in the console:

.. literalinclude:: dissect_with_separator_result.txt
    :language: text
