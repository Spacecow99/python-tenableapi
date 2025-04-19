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