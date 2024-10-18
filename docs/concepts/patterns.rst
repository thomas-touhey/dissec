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
