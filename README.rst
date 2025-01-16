``dissec`` -- Dissect pattern implementation for ElasticSearch
==============================================================

    He attac, he protec, but most importantly, he dissec.

``dissec`` is a Python module used for implementing string dissection patterns,
compatible with ElasticSearch's `Dissect processor`_.

The project is present at the following locations:

* `Official website and documentation <Website_>`_;
* `Official repository on Gitlab <Gitlab repository_>`_;
* `Official project on PyPI <PyPI project_>`_.

For example, you can dissect a string using this module with the following
snippet:

.. code-block:: python

    from dissec.patterns import Pattern

    pattern = Pattern.parse(
        r'%{clientip} %{ident} %{auth} [%{@timestamp}] \"%{verb} %{request} '
        + r'HTTP/%{httpversion}\" %{status} %{size}',
    )
    result = pattern.dissect(
        r'1.2.3.4 - - [30/Apr/1998:22:00:52 +0000] '
        + r'\"GET /english/venues/cities/images/montpellier/18.gif '
        + r'HTTP/1.0\" 200 3171',
    )
    print(result)

This will print the following, pretty-printed here for readability purposes:

.. code-block:: text

    {'@timestamp': '30/Apr/1998:22:00:52 +0000',
     'auth': '-',
     'clientip': '1.2.3.4',
     'httpversion': '1.0',
     'ident': '-',
     'request': '/english/venues/cities/images/montpellier/18.gif',
     'size': '3171',
     'status': '200',
     'verb': 'GET'}

See `Dissecting a string using dissect patterns`_ for more details on this
usage.

.. _Website: https://dissec.touhey.pro/
.. _Gitlab repository: https://gitlab.com/kaquel/dissec
.. _PyPI project: https://pypi.org/project/dissec/
.. _Dissect processor:
    https://www.elastic.co/guide/en/elasticsearch/reference/current/
    dissect-processor.html
.. _Dissecting a string using dissect patterns:
    https://dissec.touhey.pro/developer-guides/dissect.html
