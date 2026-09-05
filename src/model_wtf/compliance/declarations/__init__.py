"""Schemas and loader for the files inside a ``compliance/`` folder.

A compliance folder is a tree of small YAML files whose *file name is the
id* (``data/people.account.yaml`` declares the data object
``people.account``). This package knows every kind of file that may live
there, validates each one against a Pydantic schema, and checks that the
references between them (activity → recipient, data object → actor, ...)
resolve. It never writes anything.
"""
