"""
NOTE: This params have not been validated against the API
"""

from dataclasses import dataclass

from tenable_api import QueryParamter

# TODO: Validate that query formats are correct

# Search Audit Files

@dataclass
class Codename(QueryParamter):
    """
    """
    label: str = "Codename"
    value: str = "codename"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'
    
@dataclass
class Name(QueryParamter):
    """
    """
    label: str = "Name"
    value: str = "name"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'
    
@dataclass
class Type(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "Type"
    value: str = "indicator_type"
    # Repeats for each parameter option
    indicators_of_attack: str = str("Indicators of Attack")
    active_directory_indicators_of_exposure: str = str("Active Directory Indicators of Exposure")
    microsoft_entra_id_indicators_of_exposure: str = str("Microsoft Entra ID Indicators of Exposure")

@dataclass
class Severity(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "Severity"
    value: str = "criticity"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")


@dataclass
class Language(QueryParamter):
    """
    Parameters:
        english (str): English
        日本語 (str): Japanese

        简体中文 (str): Simplified Chinese
        繁體中文 (str): Traditional Chinese
    """
    label: str = "Language"
    value: str = "language_code"
    # Repeats for each parameter option
    english: str = str("en_US")
    deutsch: str = str("de_DE")
    francais: str = str("fr_FR")
    日本語: str = str("ja_JP")
    简体中文: str = str("zh_CN")
    繁體中文: str = str("zh_TW")
    
    def __call__(self, *args):
        """
        Format search query
        language_code: (en_US OR ja_JP OR zh_CN OR zh_TW)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'