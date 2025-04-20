"""
NOTE: This params have not been validated against the API
"""

from dataclasses import dataclass

from tenable_api import QueryParamter

# TODO: Validate that query formats are correct

@dataclass
class CVEID(QueryParamter):
    """
    """
    label: str = "CVE ID"
    value: str = "public_display"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class DatePublished(QueryParamter):
    """
    """
    label: str = "Date Published"
    value: str = "plugin_publication_date"
    
    def __call__(self, from_date, to_date):
        """
        Format search query
        plugin_publication_date: ([from_date TO to_date])
        """
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{self.value}:([{from_date} TO {to_date}])'


@dataclass
class DateModified(QueryParamter):
    """
    """
    label: str = "Date Modified"
    value: str = "plugin_modification_date"
    
    def __call__(self, from_date, to_date):
        """
        Format search query
        plugin_modification_date: ([from_date TO to_date])
        """
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{self.value}:([{from_date} TO {to_date}])'
    
@dataclass
class CVSSv2Severity(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "CVSS v2 Severity"
    value: str = "risk_factor"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")


@dataclass
class CVSSv3Severity(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "CVSS v3 Severity"
    value: str = "risk_factor_v3"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")
    
    def __call__(self, *args):
        """
        Format search query
        risk_factor_v3: (critical OR high OR medium OR low OR info)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'
    

@dataclass
class CVSSv4Severity(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "CVSS v4 Severity"
    value: str = "risk_factor_v4"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")
    
    def __call__(self, *args):
        """
        Format search query
        risk_factor_v4: (critical OR high OR medium OR low OR info)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'