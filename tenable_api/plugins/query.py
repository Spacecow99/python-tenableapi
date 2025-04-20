
"""

"""

from dataclasses import dataclass

from tenable_api import QueryParamter


@dataclass
class Product(QueryParamter):
    """
    
    Parameters:
        nessus (str): Nessus
        web_app_scanning (str): Web Application Scanning
        nessus_network_monitor (str): Nessus Network Monitor
        log_correlation_engine (str): Log Correlation Engine
        tenable_ot_security (str): Tenable OT Security
    """
    label: str = "Product"
    value: str = "sensor"
    # Repeats for each parameter option
    nessus: str = str("nessus")
    web_app_scanning: str = str("tenable_was")
    nessus_network_monitor: str = str("tenable_nnm")
    log_correlation_engine: str = str("tenable_lce")
    tenable_ot_security: str = str("tenable_ot")
    
    def __call__(self, *args):
        """
        Format search query
        sensor: (nessus OR tenable_was OR tenable_nnm OR tenable_lce OR tenable_ot)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


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
    
    def __call__(self, *args):
        """
        Format search query
        risk_factor: (critical OR high OR medium OR low OR info)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


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


@dataclass
class VPRSeverity(QueryParamter):
    """
    Parameters:
        critical (str): Critical
        high (str): High
        medium (str): Medium
        low (str): Low
        info (str): Info
    """
    label: str = "VPR Severity"
    value: str = "vpr_score"
    # Repeats for each parameter option
    critical: str = str("[9.0 TO 10.0]")
    high: str = str("[7.0 TO 8.9]")
    medium: str = str("[4.0 TO 6.9]")
    low: str = str("[0.1 TO 3.9]")
    info: str = str("0.0")
    
    def __call__(self, *args):
        """
        Format search query
        vpr_score: ([9.0 TO 10.0] OR [7.0 TO 8.9] OR [4.0 TO 6.9] OR [0.1 TO 3.9] OR 0.0)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVSSScoreSource(QueryParamter):
    """
    Parameters:
        manual (str): Manual
    """
    label: str = "CVSS Score Source"
    value: str = "cvss_score_source"
    # Repeats for each parameter option
    manual: str = str("manual")
    
    def __call__(self, *args):
        """
        Format search query
        cvss_score_source: (manual)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


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


@dataclass
class PluginID(QueryParamter):
    """
    """
    label: str = "Plugin ID"
    value: str = "script_id"
    
    def __call__(self, text: str):
        """
        Format search query
        script_id: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class Filename(QueryParamter):
    """
    """
    label: str = "Filename"
    value: str = "filename"
    
    def __call__(self, text: str):
        """
        Format search query
        filename: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class PluginName(QueryParamter):
    """
    """
    label: str = "Plugin Name"
    value: str = "script_name"
    
    def __call__(self, text: str):
        """
        Format search query
        script_name: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class Type(QueryParamter):
    """
    Parameters:
        local (str): Local
        remote (str): Remote
        combined (str): Combined
    """
    label: str = "Type"
    value: str = "plugin_type"
    # Repeats for each parameter option
    local: str = str("local")
    remote: str = str("remote")
    combined: str = str("combined")
    
    def __call__(self, *args):
        """
        Format search query
        plugin_type: (local OR remote OR combined)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Family(QueryParamter):
    """
    Parameters:
        aix_local_security_checks (str): AIX Local Security Checks
        alma_linux_local_security_checks (str): Alma Linux Local Security Checks
        amazon_linux_local_security_checks (str): Amazon Linux Local Security Checks
        artificial_intelligence (str): Artificial Intelligence
        authentication_and_session (str): Authentication %26 Session
        backdoors (str): Backdoors
        brute_force_attacks (str): Brute force attacks
        cgi (str): CGI
        cgi_abuses (str): CGI abuses
        cgi_abuses__xss (str): CGI abuses : XSS
        cisco (str): CISCO
        centos_local_security_checks (str): CentOS Local Security Checks
        cloud_services (str): Cloud Services
        code_execution (str): Code Execution
        component_vulnerability (str): Component Vulnerability
        cross_site_request_forgery (str): Cross Site Request Forgery
        cross_site_scripting (str): Cross Site Scripting
        dns (str): DNS
        dns_servers (str): DNS Servers
        data_exposure (str): Data Exposure
        data_leakage (str): Data Leakage
        database (str): Database
        databases (str): Databases
        debian_local_security_checks (str): Debian Local Security Checks
        default_unix_accounts (str): Default Unix Accounts
        denial_of_service (str): Denial of Service
        f5_networks_local_security_checks (str): F5 Networks Local Security Checks
        ftp (str): FTP
        ftp_clients (str): FTP Clients
        ftp_servers (str): FTP Servers
        fedora_local_security_checks (str): Fedora Local Security Checks
        file_inclusion (str): File Inclusion
        finger (str): Finger
        firewalls (str): Firewalls
        freebsd_local_security_checks (str): FreeBSD Local Security Checks
        gain_a_shell_remotely (str): Gain a shell remotely
        general (str): General
        generic (str): Generic
        gentoo_local_security_checks (str): Gentoo Local Security Checks
        hp_ux_local_security_checks (str): HP-UX Local Security Checks
        huawei_local_security_checks (str): Huawei Local Security Checks
        imap_servers (str): IMAP Servers
        irc_clients (str): IRC Clients
        irc_servers (str): IRC Servers
        incident_response (str): Incident Response
        injection (str): Injection
        internet_messengers (str): Internet Messengers
        internet_services (str): Internet Services
        iot (str): IoT
        junos_local_security_checks (str): Junos Local Security Checks
        macos_x_local_security_checks (str): MacOS X Local Security Checks
        mandriva_local_security_checks (str): Mandriva Local Security Checks
        misc (str): Misc.
        mobile_devices (str): Mobile Devices
        netware (str): Netware
        newstart_cgsl_local_security_checks (str): NewStart CGSL Local Security Checks
        operating_system_detection (str): Operating System Detection
        oracle_linux_local_security_checks (str): Oracle Linux Local Security Checks
        oraclevm_local_security_checks (str): OracleVM Local Security Checks
        pop_server (str): POP Server
        palo_alto_local_security_checks (str): Palo Alto Local Security Checks
        peer_to_peer_file_sharing (str): Peer-To-Peer File Sharing
        photonos_local_security_checks (str): PhotonOS Local Security Checks
        policy (str): Policy
        policy_compliance (str): Policy Compliance
        port_scanners (str): Port scanners
        rpc (str): RPC
        red_hat_local_security_checks (str): Red Hat Local Security Checks
        rocky_linux_local_security_checks (str): Rocky Linux Local Security Checks
        scada (str): SCADA
        smtp_clients (str): SMTP Clients
        smtp_servers (str): SMTP Servers
        smtp_problems (str): SMTP problems
        snmp (str): SNMP
        ssh (str): SSH
        samba (str): Samba
        scientific_linux_local_security_checks (str): Scientific Linux Local Security Checks
        service_detection (str): Service detection
        settings (str): Settings
        slackware_local_security_checks (str): Slackware Local Security Checks
        solaris_local_security_checks (str): Solaris Local Security Checks
        suse_local_security_checks (str): SuSE Local Security Checks
        ubuntu_local_security_checks (str): Ubuntu Local Security Checks
        vmware_esx_local_security_checks (str): VMware ESX Local Security Checks
        virtuozzo_local_security_checks (str): Virtuozzo Local Security Checks
        web_applications (str): Web Applications
        web_clients (str): Web Clients
        web_servers (str): Web Servers
        windows (str): Windows
        windows__microsoft_bulletins (str): Windows : Microsoft Bulletins
        windows__user_management (str): Windows : User management
    """
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
        """
        Format search query
        script_family: (AIX Local Security Checks OR Alma Linux Local Security Checks)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


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
class AgentCapable(QueryParamter):
    """
    Parameters:
        windows (str): Windows
        macos (str): MacOS
        unix (str): Unix
    """
    label: str = "Agent Capable"
    value: str = "agent"
    # Repeats for each parameter option
    windows: str = str("windows")
    macos: str = str("macosx")
    unix: str = str("unix")
    
    def __call__(self, *args):
        """
        Format search query
        agent: (windows OR macosx OR unix)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Dependencies(QueryParamter):
    """
    """
    label: str = "Dependencies"
    value: str = "dependencies"
    
    def __call__(self, text: str):
        """
        Format search query
        dependencies: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class IntheNews(QueryParamter):
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "In the News"
    value: str = "in_the_news"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        """
        Format search query
        in_the_news: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableParanoidMode(QueryParamter):
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "Enable Paranoid Mode"
    value: str = "enable_paranoid_mode"
    # Repeats for each parameter option
    yes: str = str("True")
    
    def __call__(self, *args):
        """
        Format search query
        enable_paranoid_mode: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableDefaultLogins(QueryParamter):
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "Enable Default Logins"
    value: str = "enable_default_logins"
    # Repeats for each parameter option
    yes: str = str("True")
    
    def __call__(self, *args):
        """
        Format search query
        enable_default_logins: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableThoroughTests(QueryParamter):
    """
    Parameters:
        yes (str): Yes
        no (str): No
    """
    label: str = "Enable Thorough Tests"
    value: str = "thorough_tests"
    # Repeats for each parameter option
    yes: str = str("True")
    no: str = str("False")
    
    def __call__(self, *args):
        """
        Format search query
        thorough_tests: (true OR false)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class EnableCGIScanning(QueryParamter):
    """
    Parameters:
        yes (str): Yes
        no (str): No
    """
    label: str = "Enable CGI Scanning"
    value: str = "enable_cgi_scanning"
    # Repeats for each parameter option
    yes: str = str("True")
    no: str = str("False")
    
    def __call__(self, *args):
        """
        Format search query
        enable_cgi_scanning: (true OR false)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class ExploitAvailable:
    """
    Parameters:
        yes (str): Yes
        no (str): No
    """
    label: str = "Exploit Available"
    value: str = "exploit_available"
    # Repeats for each parameter option
    yes: str = str("true")
    no: str = str("false")
    
    def __call__(self, *args):
        """
        Format search query
        exploit_available: (true OR false)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CISAKnownExploited:
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "CISA Known Exploited"
    value: str = "cisa_known_exploited"
    # Repeats for each parameter option
    yes: str = str("references.id.keyword")
    
    def __call__(self, *args):
        """
        Format search query
        cisa_known_exploited: (references.id.keyword)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class CVE:
    """
    """
    label: str = "CVE"
    value: str = "cves"
    
    def __call__(self, text: str):
        """
        Format search query
        cves: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class Bugtraq:
    """
    """
    label: str = "Bugtraq"
    value: str = "bids"
    
    def __call__(self, text: str):
        """
        Format search query
        bids: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CPE:
    """
    """
    label: str = "CPE"
    value: str = "cpe"
    
    def __call__(self, text: str):
        """
        Format search query
        cpe: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class RequiredKBItems:
    """
    """
    label: str = "Required KB Items"
    value: str = "required_keys"
    
    def __call__(self, text: str):
        """
        Format search query
        required_keys: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class ExcludedKBItems:
    """
    """
    label: str = "Excluded KB Items"
    value: str = "excluded_keys"
    
    def __call__(self, text: str):
        """
        Format search query
        excluded_keys: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class RequiredPorts:
    """
    """
    label: str = "Required Ports"
    value: str = "script_required_ports"
    
    def __call__(self, text: str):
        """
        Format search query
        script_required_ports: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CWE:
    """
    """
    label: str = "CWE"
    value: str = "xrefs.CWE"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CWE: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class WASC:
    """
    """
    label: str = "WASC"
    value: str = "xrefs.WASC"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.WASC: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class OWASP:
    """
    """
    label: str = "OWASP"
    value: str = "xrefs.OWASP"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.OWASP: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class OWASPAPI:
    """
    """
    label: str = "OWASP API"
    value: str = "xrefs.OWASP_API"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.OWASP_API: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class ALAS:
    """
    """
    label: str = "ALAS"
    value: str = "xrefs.ALAS"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.ALAS: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CiscoBugID:
    """
    """
    label: str = "Cisco Bug ID"
    value: str = "xrefs.CISCO-BUG-ID"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CISCO-BUG-ID: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CiscoSecurityAdvisory:
    """
    """
    label: str = "Cisco Security Advisory"
    value: str = "xrefs.CISCO-SA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CISCO-SA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CiscoSecurityResponse:
    """
    """
    label: str = "Cisco Security Response"
    value: str = "xrefs.CISCO-SR"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CISCO-SR: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class RHSA:
    """
    """
    label: str = "RHSA"
    value: str = "xrefs.RHSA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.RHSA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class FedoraSecurityAdvisories:
    """
    """
    label: str = "Fedora Security Advisories"
    value: str = "xrefs.FEDORA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.FEDORA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class MicrosoftKB:
    """
    """
    label: str = "Microsoft KB"
    value: str = "xrefs.MSKB"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.MSKB: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class UbuntuSecurityNotices:
    """
    """
    label: str = "Ubuntu Security Notices"
    value: str = "xrefs.USN"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.USN: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class SecuniaAdvisories:
    """
    """
    label: str = "Secunia Advisories"
    value: str = "xrefs.SECUNIA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.SECUNIA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class VMwareSecurityAdvisories:
    """
    """
    label: str = "VMware Security Advisories"
    value: str = "xrefs.VMSA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.VMSA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CERT:
    """
    """
    label: str = "CERT"
    value: str = "xrefs.CERT"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CERT: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class CERTCC:
    """
    """
    label: str = "CERT-CC"
    value: str = "xrefs.CERT-CC"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.CERT-CC: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class IAVA:
    """
    """
    label: str = "IAVA"
    value: str = "xrefs.IAVA"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.IAVA: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class IAVB:
    """
    """
    label: str = "IAVB"
    value: str = "xrefs.IAVB"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.IAVB: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class ExploitDatabase:
    """
    """
    label: str = "Exploit Database"
    value: str = "xrefs.EDB-ID"
    
    def __call__(self, text: str):
        """
        Format search query
        xrefs.EDB-ID: ("text")
        """
        return f'{self.value}:("{text}")'


@dataclass
class AssetInventory:
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "Asset Inventory"
    value: str = "asset_inventory"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        """
        Format search query
        asset_inventory: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class HardwareInventory:
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "Hardware Inventory"
    value: str = "hardware_inventory"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        """
        Format search query
        hardware_inventory: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class OSIdentification:
    """
    Parameters:
        yes (str): Yes
    """
    label: str = "OS Identification"
    value: str = "os_identification"
    # Repeats for each parameter option
    yes: str = str("true")
    
    def __call__(self, *args):
        """
        Format search query
        os_identification: (true)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class WASScanTemplate:
    """
    Parameters:
        api (str): API
        basic (str): Basic
        config_audit (str): Config Audit
        full (str): Full
        overview (str): Overview
        pci (str): PCI
        scan (str): Scan
        ssl_tls (str): SSL/TLS
        log4shell (str): Log4Shell
    """
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
        """
        Format search query
        policy: (api OR basic OR config_audit OR full OR overview OR pci OR scan OR ssl_tls OR log4shell)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class SupportedSensors:
    """
    Parameters:
        nessus (str): Nessus
        nessus_agent (str): Nessus Agent
        agentless_assessment (str): Agentless Assessment
        frictionless_assessment_azure (str): Frictionless Assessment Azure
        frictionless_assessment_aws (str): Frictionless Assessment AWS
        frictionless_assessment_agent (str): Frictionless Assessment Agent
        tenable_ot_security (str): Tenable OT Security
        continuous_assessment (str): Continuous Assessment
    """
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
        """
        Format search query
        supported_sensors: (nessus OR nessus_agent OR agentless_assessment OR fa_azure OR fa_aws OR fa_agent OR ot_security OR continuous_assessment)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class VendorSeverity:
    """
    """
    label: str = "Vendor Severity"
    value: str = "vendor_severity"
    
    def __call__(self, text: str):
        """
        Format search query
        vendor_severity: ("text")
        """
        return f'{self.value}:("{text}")'

