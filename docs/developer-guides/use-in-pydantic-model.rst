Using dissect patterns in Pydantic models
=========================================

.. py:currentmodule:: dissec.patterns

You can use dissect patterns as fields in Pydantic models directly, by
annotating a field with :py:class:`Pattern`:

.. literalinclude:: use_in_pydantic_model.py
    :language: python

The above script displays the following in the console:

.. code-block:: text

    {"my_pattern":"%{hello} - %{world}"}

This setup has the advantage of validating the pattern in the provided fields,
and yielding exceptions in case of invalid patterns. For example:

.. literalinclude:: use_in_pydantic_model_with_invalid_values.py
    :language: python

This script displays the following in the console:

.. literalinclude:: use_in_pydantic_model_with_invalid_values_result.txt
    :language: text
