#!/usr/bin/env python3

"""
A wrapper around the tenable.com public API.
"""

__version__ = "0.0.1"


from tenable_api.attack_path_techniques import AttackPathTechniques
from tenable_api.audits import Audits
from tenable_api.cve import CVE
from tenable_api.indicators import Indicators
from tenable_api.plugins import Plugins
from tenable_api.plugins import query


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