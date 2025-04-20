"""
NOTE: This params have not been validated against the API
"""

from dataclasses import dataclass

from tenable_api import QueryParamter

# TODO: Validate that query formats are correct

# Search Audit Files

@dataclass
class Filename(QueryParamter):
    """
    """
    label: str = "Filename"
    value: str = "filename"
    
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
    value: str = "display_name"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class UpdatedDate(QueryParamter):
    """
    """
    label: str = "Updated Date"
    value: str = "date"
    
    def __call__(self, from_date, to_date):
        """
        Format search query
        plugin_publication_date: ([from_date TO to_date])
        """
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{self.value}:([{from_date} TO {to_date}])'

@dataclass
class Authority(QueryParamter):
    """
    Parameters:
        manual (str): Manual
    """
    label: str = "Authority"
    value: str = "type"
    # Repeats for each parameter option
    cis: str = str("CIS")
    disa_stig: str = str("DISA STIG")
    msct: str = str("MSCT")
    tns: str = str("TNS")
    vendor: str = str("VENDOR")
    
    def __call__(self, *args):
        """
        Format search query
        cvss_score_source: (manual)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'

@dataclass
class Plugin(QueryParamter):
    """
    Parameters:
        manual (str): Manual
    """
    label: str = "Plugin"
    value: str = "plugin"
    # Repeats for each parameter option
    as_400: str = str("AS/400")
    adtran: str = str("Adtran")
    alcatel: str = str("Alcatel")
    arista: str = str("Arista")
    arubaos: str = str("ArubaOS")
    bluecoat: str = str("BlueCoat")
    brocade: str = str("Brocade")
    checkpoint: str = str("CheckPoint")
    cisco: str = str("Cisco")
    cisco_aci: str = str("Cisco_ACI")
    cisco_firepower: str = str("Cisco_Firepower")
    cisco_viptela: str = str("Cisco_Viptela")
    citrix_application_delivery: str = str("Citrix_Application_Delivery")
    database: str = str("Database")
    extreme_extremexos: str = str("Extreme_ExtremeXOS")
    f5: str = str("F5")
    filecontent: str = str("FileContent")
    fireeye: str = str("FireEye")
    fortigate: str = str("FortiGate")
    gcp: str = str("GCP")
    hp_pro_curve: str = str("HP_ProCurve")
    huawei: str = str("Huawei")
    ibm_db2db: str = str("IBM_DB2DB")
    juniper: str = str("Juniper")
    mdm: str = str("MDM")
    mongodb: str = str("MongoDB")
    ms_sqldb: str = str("MS_SQLDB")
    mysql: str = str("MySQLDB")
    netapp: str = str("NetApp")
    netapp_api: str = str("Netapp_API")
    openshift: str = str("OpenShift")
    openstack: str = str("OpenStack")
    oracledb: str = str("OracleDB")
    palo_alto: str = str("Palo_Alto")
    postgresql: str = str("PostgreSQLDB")
    rhev: str = str("RHEV")
    rackspace: str = str("Rackspace")
    salesforce: str = str("Salesforce.com")
    sonicwall: str = str("SonicWALL")
    splunk: str = str("Splunk")
    sybase: str = str("Sybase")
    unix: str = str("Unix")
    vmware: str = str("VMware")
    watchguard: str = str("WatchGuard")
    windows: str = str("Windows")
    windows_files: str = str("WindowsFiles")
    zte_rosng: str = str("ZTE_ROSNG")
    zoom: str = str("Zoom")
    amazon_aws: str = str("amazon_aws")
    microsoft_azure: str = str("microsoft_azure")
    
    def __call__(self, *args):
        """
        Format search query
        cvss_score_source: (manual)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


# Search Items

@dataclass
class Description(QueryParamter):
    """
    """
    label: str = "Description"
    value: str = "description"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'

@dataclass
class AuditName(QueryParamter):
    """
    """
    label: str = "Filename"
    value: str = "audit_name"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'

@dataclass
class References(QueryParamter):
    """
    """
    label: str = "References"
    value: str = "references"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'

@dataclass
class ControlID(QueryParamter):
    """
    """
    label: str = "Control ID"
    value: str = "controlId"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'

