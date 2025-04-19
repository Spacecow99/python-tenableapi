
"""

"""

from dataclasses import dataclass

class QueryParamter():
    def __call__(self):
        raise NotImplementedError("Subclasses must implement this method")

@dataclass
class Product(QueryParamter):
    label: str = "Product"
    value: str = "sensor"
    # Repeats for each parameter option
    nessus: str = str("nessus")
    web_app_scanning: str = str("tenable_was")
    nessus_network_monitor: str = str("tenable_nnm")
    log_correlation_engine: str = str("tenable_lce")
    tenable_ot_security: str = str("tenable_ot")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVSSv2Severity(QueryParamter):
    label: str = "CVSS v2 Severity"
    value: str = "risk_factor"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVSSv3Severity(QueryParamter):
    label: str = "CVSS v3 Severity"
    value: str = "risk_factor_v3"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVSSv4Severity(QueryParamter):
    label: str = "CVSS v4 Severity"
    value: str = "risk_factor_v4"
    # Repeats for each parameter option
    critical: str = str("critical")
    high: str = str("high")
    medium: str = str("medium")
    low: str = str("low")
    info: str = str("info")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class VPRSeverity(QueryParamter):
    label: str = "VPR Severity"
    value: str = "vpr_score"
    # Repeats for each parameter option
    critical: str = str("[9.0 TO 10.0]")
    high: str = str("[7.0 TO 8.9]")
    medium: str = str("[4.0 TO 6.9]")
    low: str = str("[0.1 TO 3.9]")
    info: str = str("0.0")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVSSScoreSource(QueryParamter):
    label: str = "CVSS Score Source"
    value: str = "cvss_score_source"
    # Repeats for each parameter option
    manual: str = str("manual")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Language(QueryParamter):
    label: str = "Language"
    value: str = "language_code"
    # Repeats for each parameter option
    english: str = str("en_US")
    日本語: str = str("ja_JP")
    简体中文: str = str("zh_CN")
    繁體中文: str = str("zh_TW")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class PluginID(QueryParamter):
    label: str = "Plugin ID"
    value: str = "script_id"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class Filename(QueryParamter):
    label: str = "Filename"
    value: str = "filename"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class PluginName(QueryParamter):
    label: str = "Plugin Name"
    value: str = "script_name"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class Type(QueryParamter):
    label: str = "Type"
    value: str = "plugin_type"
    # Repeats for each parameter option
    local: str = str("local")
    remote: str = str("remote")
    combined: str = str("combined")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Family(QueryParamter):
    label: str = "Family"
    value: str = "script_family"
    # Repeats for each parameter option
    aix_local_security_checks: str = str("AIX Local Security Checks")
    alma_linux_local_security_checks: str = str("Alma Linux Local Security Checks")
    amazon_linux_local_security_checks: str = str("Amazon Linux Local Security Checks")
    artificial_intelligence: str = str("Artificial Intelligence")
    authentication_and_session: str = str("Authentication %26 Session")
    backdoors: str = str("Backdoors")
    brute_force_attacks: str = str("Brute force attacks")
    cgi: str = str("CGI")
    cgi_abuses: str = str("CGI abuses")
    cgi_abuses__xss: str = str("CGI abuses : XSS")
    cisco: str = str("CISCO")
    centos_local_security_checks: str = str("CentOS Local Security Checks")
    cloud_services: str = str("Cloud Services")
    code_execution: str = str("Code Execution")
    component_vulnerability: str = str("Component Vulnerability")
    cross_site_request_forgery: str = str("Cross Site Request Forgery")
    cross_site_scripting: str = str("Cross Site Scripting")
    dns: str = str("DNS")
    dns_servers: str = str("DNS Servers")
    data_exposure: str = str("Data Exposure")
    data_leakage: str = str("Data Leakage")
    database: str = str("Database")
    databases: str = str("Databases")
    debian_local_security_checks: str = str("Debian Local Security Checks")
    default_unix_accounts: str = str("Default Unix Accounts")
    denial_of_service: str = str("Denial of Service")
    f5_networks_local_security_checks: str = str("F5 Networks Local Security Checks")
    ftp: str = str("FTP")
    ftp_clients: str = str("FTP Clients")
    ftp_servers: str = str("FTP Servers")
    fedora_local_security_checks: str = str("Fedora Local Security Checks")
    file_inclusion: str = str("File Inclusion")
    finger: str = str("Finger")
    firewalls: str = str("Firewalls")
    freebsd_local_security_checks: str = str("FreeBSD Local Security Checks")
    gain_a_shell_remotely: str = str("Gain a shell remotely")
    general: str = str("General")
    generic: str = str("Generic")
    gentoo_local_security_checks: str = str("Gentoo Local Security Checks")
    hp_ux_local_security_checks: str = str("HP-UX Local Security Checks")
    huawei_local_security_checks: str = str("Huawei Local Security Checks")
    imap_servers: str = str("IMAP Servers")
    irc_clients: str = str("IRC Clients")
    irc_servers: str = str("IRC Servers")
    incident_response: str = str("Incident Response")
    injection: str = str("Injection")
    internet_messengers: str = str("Internet Messengers")
    internet_services: str = str("Internet Services")
    iot: str = str("IoT")
    junos_local_security_checks: str = str("Junos Local Security Checks")
    macos_x_local_security_checks: str = str("MacOS X Local Security Checks")
    mandriva_local_security_checks: str = str("Mandriva Local Security Checks")
    misc: str = str("Misc.")
    mobile_devices: str = str("Mobile Devices")
    netware: str = str("Netware")
    newstart_cgsl_local_security_checks: str = str("NewStart CGSL Local Security Checks")
    operating_system_detection: str = str("Operating System Detection")
    oracle_linux_local_security_checks: str = str("Oracle Linux Local Security Checks")
    oraclevm_local_security_checks: str = str("OracleVM Local Security Checks")
    pop_server: str = str("POP Server")
    palo_alto_local_security_checks: str = str("Palo Alto Local Security Checks")
    peer_to_peer_file_sharing: str = str("Peer-To-Peer File Sharing")
    photonos_local_security_checks: str = str("PhotonOS Local Security Checks")
    policy: str = str("Policy")
    policy_compliance: str = str("Policy Compliance")
    port_scanners: str = str("Port scanners")
    rpc: str = str("RPC")
    red_hat_local_security_checks: str = str("Red Hat Local Security Checks")
    rocky_linux_local_security_checks: str = str("Rocky Linux Local Security Checks")
    scada: str = str("SCADA")
    smtp_clients: str = str("SMTP Clients")
    smtp_servers: str = str("SMTP Servers")
    smtp_problems: str = str("SMTP problems")
    snmp: str = str("SNMP")
    ssh: str = str("SSH")
    samba: str = str("Samba")
    scientific_linux_local_security_checks: str = str("Scientific Linux Local Security Checks")
    service_detection: str = str("Service detection")
    settings: str = str("Settings")
    slackware_local_security_checks: str = str("Slackware Local Security Checks")
    solaris_local_security_checks: str = str("Solaris Local Security Checks")
    suse_local_security_checks: str = str("SuSE Local Security Checks")
    ubuntu_local_security_checks: str = str("Ubuntu Local Security Checks")
    vmware_esx_local_security_checks: str = str("VMware ESX Local Security Checks")
    virtuozzo_local_security_checks: str = str("Virtuozzo Local Security Checks")
    web_applications: str = str("Web Applications")
    web_clients: str = str("Web Clients")
    web_servers: str = str("Web Servers")
    windows: str = str("Windows")
    windows__microsoft_bulletins: str = str("Windows : Microsoft Bulletins")
    windows__user_management: str = str("Windows : User management")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class DatePublished(QueryParamter):
    label: str = "Date Published"
    value: str = "plugin_publication_date"
    
    def __call__(self, from_date, to_date):
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{self.value}:([{from_date} TO {to_date}])'


@dataclass
class DateModified(QueryParamter):
    label: str = "Date Modified"
    value: str = "plugin_modification_date"
    
    def __call__(self, from_date, to_date):
        if to_date < from_date:
            raise Exception("to_date must be greater than from_date")
        return f'{self.value}:([{from_date} TO {to_date}])'


@dataclass
class AgentCapable(QueryParamter):
    label: str = "Agent Capable"
    value: str = "agent"
    # Repeats for each parameter option
    windows: str = str("windows")
    macos: str = str("macosx")
    unix: str = str("unix")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Dependencies(QueryParamter):
    label: str = "Dependencies"
    value: str = "dependencies"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class IntheNews(QueryParamter):
    label: str = "In the News"
    value: str = "in_the_news"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableParanoidMode(QueryParamter):
    label: str = "Enable Paranoid Mode"
    value: str = "enable_paranoid_mode"
    # Repeats for each parameter option
    yes: str = str("True")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableDefaultLogins(QueryParamter):
    label: str = "Enable Default Logins"
    value: str = "enable_default_logins"
    # Repeats for each parameter option
    yes: str = str("True")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableThoroughTests(QueryParamter):
    label: str = "Enable Thorough Tests"
    value: str = "thorough_tests"
    # Repeats for each parameter option
    yes: str = str("True")
    no: str = str("False")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableCGIScanning(QueryParamter):
    label: str = "Enable CGI Scanning"
    value: str = "enable_cgi_scanning"
    # Repeats for each parameter option
    yes: str = str("True")
    no: str = str("False")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class ExploitAvailable:
    label: str = "Exploit Available"
    value: str = "exploit_available"
    # Repeats for each parameter option
    yes: str = str("true")
    no: str = str("false")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CISAKnownExploited:
    label: str = "CISA Known Exploited"
    value: str = "cisa_known_exploited"
    # Repeats for each parameter option
    yes: str = str("references.id.keyword")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVE:
    label: str = "CVE"
    value: str = "cves"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class Bugtraq:
    label: str = "Bugtraq"
    value: str = "bids"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CPE:
    label: str = "CPE"
    value: str = "cpe"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class RequiredKBItems:
    label: str = "Required KB Items"
    value: str = "required_keys"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class ExcludedKBItems:
    label: str = "Excluded KB Items"
    value: str = "excluded_keys"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class RequiredPorts:
    label: str = "Required Ports"
    value: str = "script_required_ports"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CWE:
    label: str = "CWE"
    value: str = "xrefs.CWE"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class WASC:
    label: str = "WASC"
    value: str = "xrefs.WASC"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class OWASP:
    label: str = "OWASP"
    value: str = "xrefs.OWASP"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class OWASPAPI:
    label: str = "OWASP API"
    value: str = "xrefs.OWASP_API"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class ALAS:
    label: str = "ALAS"
    value: str = "xrefs.ALAS"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CiscoBugID:
    label: str = "Cisco Bug ID"
    value: str = "xrefs.CISCO-BUG-ID"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CiscoSecurityAdvisory:
    label: str = "Cisco Security Advisory"
    value: str = "xrefs.CISCO-SA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CiscoSecurityResponse:
    label: str = "Cisco Security Response"
    value: str = "xrefs.CISCO-SR"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class RHSA:
    label: str = "RHSA"
    value: str = "xrefs.RHSA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class FedoraSecurityAdvisories:
    label: str = "Fedora Security Advisories"
    value: str = "xrefs.FEDORA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class MicrosoftKB:
    label: str = "Microsoft KB"
    value: str = "xrefs.MSKB"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class UbuntuSecurityNotices:
    label: str = "Ubuntu Security Notices"
    value: str = "xrefs.USN"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class SecuniaAdvisories:
    label: str = "Secunia Advisories"
    value: str = "xrefs.SECUNIA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class VMwareSecurityAdvisories:
    label: str = "VMware Security Advisories"
    value: str = "xrefs.VMSA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CERT:
    label: str = "CERT"
    value: str = "xrefs.CERT"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class CERTCC:
    label: str = "CERT-CC"
    value: str = "xrefs.CERT-CC"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class IAVA:
    label: str = "IAVA"
    value: str = "xrefs.IAVA"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class IAVB:
    label: str = "IAVB"
    value: str = "xrefs.IAVB"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class ExploitDatabase:
    label: str = "Exploit Database"
    value: str = "xrefs.EDB-ID"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'


@dataclass
class AssetInventory:
    label: str = "Asset Inventory"
    value: str = "asset_inventory"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class HardwareInventory:
    label: str = "Hardware Inventory"
    value: str = "hardware_inventory"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class OSIdentification:
    label: str = "OS Identification"
    value: str = "os_identification"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class WASScanTemplate:
    label: str = "WAS Scan Template"
    value: str = "policy"
    # Repeats for each parameter option
    api: str = str("api")
    basic: str = str("basic")
    config_audit: str = str("config_audit")
    full: str = str("full")
    overview: str = str("overview")
    pci: str = str("pci")
    scan: str = str("scan")
    ssl_tls: str = str("ssl_tls")
    log4shell: str = str("log4shell")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class SupportedSensors:
    label: str = "Supported Sensors"
    value: str = "supported_sensors"
    # Repeats for each parameter option
    nessus: str = str("nessus")
    nessus_agent: str = str("nessus_agent")
    agentless_assessment: str = str("agentless_assessment")
    frictionless_assessment_azure: str = str("fa_azure")
    frictionless_assessment_aws: str = str("fa_aws")
    frictionless_assessment_agent: str = str("fa_agent")
    tenable_ot_security: str = str("ot_security")
    continuous_assessment: str = str("continuous_assessment")
    
    def __call__(self, *args):
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class VendorSeverity:
    label: str = "Vendor Severity"
    value: str = "vendor_severity"
    
    def __call__(self, text: str):
        return f'{self.value}:("{text}")'

