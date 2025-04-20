#!/usr/bin/env python3

"""
A wrapper around the tenable.com public API.
"""

__version__ = "0.0.1"


class QueryParamter():
    """
    Base class for all query parameters
    """
    def __call__(self):
        raise NotImplementedError("Subclasses must implement this method")


class Query():
    """
    Format search query
    args:
        args (tuple): search query
    """
    def __call__(self, *args: QueryParamter):
        return ' AND '.join(args)