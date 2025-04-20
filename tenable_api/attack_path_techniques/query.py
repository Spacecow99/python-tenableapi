"""
NOTE: This params have not been validated against the API
"""

from dataclasses import dataclass

from tenable_api import QueryParamter

# TODO: Validate that query formats are correct

@dataclass
class Name(QueryParamter):
    """
    """
    label: str = "Name"
    value: str = "attack_name"
    
    def __call__(self, text: str):
        """
        Format search query
        attack_name: ("text")
        """
        return f'{self.value}:("{text}")'
    

@dataclass
class FamilyTactic(QueryParamter):
    """
    Parameters:
        collection (str): Collection
        credential_access (str): Credential Access
        defense_evasion (str): Defense Evasion
        discovery (str): Discovery
        execution (str): Execution
        exfiltration (str): Exfiltration
        lateral_movement (str): Lateral Movement
        persistence (str): Persistence
        privilege_escalation (str): Privilege Escalation
    """
    label: str = "Family/Tactic"
    value: str = "attack_family"
    # Repeats for each parameter option
    collection: str = str("Collection")
    credential_access: str = str("Credential Access")
    defense_evasion: str = str("Defense Evasion")
    discovery: str = str("Discovery")
    execution: str = str("Execution")
    exfiltration: str = str("Exfiltration")
    lateral_movement: str = str("Lateral Movement")
    persistence: str = str("Persistence")
    privilege_escalation: str = str("Privilege Escalation")
    
    def __call__(self, *args):
        """
        Format search query
        attack_family: (collection OR credential_access)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'
    
@dataclass
class Framework(QueryParamter):
    """
    """
    label: str = "Framework"
    value: str = "attack_framework"
    
    def __call__(self, text: str):
        """
        Format search query
        attack_framework: ("text")
        """
        return f'{self.value}:("{text}")'
    

@dataclass
class Technique(QueryParamter):
    """
    Parameters:

    """
    label: str = "Technique"
    value: str = "attack_technique"
    # Repeats for each parameter option
    access_token_manipulation: str = str("Access Token Manipulation")
    account_discovery: str = str("Account Discovery")
    account_manipulation: str = str("Account Manipulation")
    adversary_in_the_middle: str = str("Adversary-in-the-Middle")
    boot_or_logon_initialization_scripts: str = str("Boot or Logon Initialization Scripts")
    brute_force: str = str("Brute Force")
    create_account: str = str("Create Account")
    data_from_cloud_storage_object: str = str("Data from Cloud Storage Object")
    domain_policy_modification: str = str("Domain Policy Modification")
    domain_trust_discovery: str = str("Domain Trust Discovery")
    email_collection_remote_email_collection: str = str("Email Collection: Remote Email Collection")
    escape_to_host: str = str("Escape to Host")
    exfiltration_over_alternative_protocol: str = str("Exfiltration Over Alternative Protocol")
    exploitation_for_client_execution: str = str("Exploitation for Client Execution")
    exploitation_for_credential_access: str = str("Exploitation for Credential Access")
    exploitation_for_defense_evasion: str = str("Exploitation for Defense Evasion")
    exploitation_for_privilege_escalation: str = str("Exploitation for Privilege Escalation")
    exploitation_of_remote_services: str = str("Exploitation of Remote Services")
    hijack_execution_flow: str = str("Hijack Execution Flow")
    hijack_execution_flow_path_interception_by_unquoted_path: str = str("Hijack Execution Flow: Path Interception by Unquoted Path")
    network_share_discovery: str = str("Network Share Discovery")
    network_sniffing: str = str("Network Sniffing")
    os_credential_dumping: str = str("OS Credential Dumping")
    permission_groups_discovery: str = str("Permission Groups Discovery")
    remote_services: str = str("Remote Services")
    rogue_domain_controller: str = str("Rogue Domain Controller")
    steal_application_access_token: str = str("Steal Application Access Token")
    steal_or_forge_kerberos_tickets: str = str("Steal or Forge Kerberos Tickets")
    system_service_discovery: str = str("System Service Discovery")
    windows_management_instrumentation: str = str("Windows Management Instrumentation")
    
    def __call__(self, *args):
        """
        Format search query
        attack_family: (collection OR credential_access)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class SubTechnique(QueryParamter):
    """
    Parameters:

    """
    label: str = "Sub-Technique"
    value: str = "attack_subtechnique"
    # Repeats for each parameter option
    as_rep_roasting: str = str("AS-REP Roasting")
    additional_cloud_roles: str = str("Additional Cloud Roles")
    brute_force_password_cracking: str = str("Brute Force: Password Cracking")
    cloud_account: str = str("Cloud Account")
    cloud_groups: str = str("Cloud Groups")
    create_process_with_token: str = str("Create Process with Token")
    dcsync: str = str("DCSync")
    data_from_cloud_storage_object: str = str("Data from Cloud Storage Object")
    domain_groups: str = str("Domain Groups")
    domain_trust_discovery: str = str("Domain Trust Discovery")
    email_collection_remote_email_collection: str = str("Email Collection: Remote Email Collection")
    escape_to_host: str = str("Escape to Host")
    exfiltration_over_asymmetric_encrypted_non_c2_protocol: str = str("Exfiltration Over Asymmetric Encrypted Non-C2 Protocol")
    exfiltration_over_symmetric_encrypted_non_c2_protocol: str = str("Exfiltration Over Symmetric Encrypted Non-C2 Protocol")
    exfiltration_over_unencrypted_obfuscated_non_c2_protocol: str = str("Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol")
    exploitation_for_client_execution: str = str("Exploitation for Client Execution")
    exploitation_for_credential_access: str = str("Exploitation for Credential Access")
    exploitation_for_defense_evasion: str = str("Exploitation for Defense Evasion")
    exploitation_for_privilege_escalation: str = str("Exploitation for Privilege Escalation")
    exploitation_of_remote_services: str = str("Exploitation of Remote Services")
    golden_ticket: str = str("Golden Ticket")
    group_policy_modification: str = str("Group Policy Modification")
    hijack_execution_flow_path_interception_by_unquoted_path: str = str("Hijack Execution Flow: Path Interception by Unquoted Path")
    impersonation_theft: str = str("Impersonation/Theft")
    kerberoasting: str = str("Kerberoasting")
    llmnr_nbt_ns_poisoning_and_smb_relay: str = str("LLMNR/NBT-NS Poisoning and SMB Relay")
    lsa_secrets: str = str("LSA Secrets")
    lsass_memory: str = str("LSASS Memory")
    ntds: str = str("NTDS")
    network_logon_script: str = str("Network Logon Script")
    network_share_discovery: str = str("Network Share Discovery")
    network_sniffing: str = str("Network Sniffing")
    password_guessing: str = str("Password Guessing")
    password_spraying: str = str("Password Spraying")
    remote_desktop_protocol: str = str("Remote Desktop Protocol")
    rogue_domain_controller: str = str("Rogue Domain Controller")
    sid_history_injection: str = str("SID-History Injection")
    smb_windows_admin_shares: str = str("SMB/Windows Admin Shares")
    security_account_manager: str = str("Security Account Manager")
    services_registry_permissions_weakness: str = str("Services Registry Permissions Weakness")
    steal_application_access_token: str = str("Steal Application Access Token")
    system_service_discovery: str = str("System Service Discovery")
    windows_management_instrumentation: str = str("Windows Management Instrumentation")
    windows_remote_management: str = str("Windows Remote Management")

    def __call__(self, *args):
        """
        Format search query
        attack_family: (collection OR credential_access)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Platform(QueryParamter):
    """
    Parameters:
        
    """
    label: str = "Platform"
    value: str = "attack_platform"
    # Repeats for each parameter option
    aws: str = str("AWS")
    microsoft_entra_id: str = str("Microsoft Entra ID")
    operational_technology: str = str("Operational Technology")
    windows: str = str("Windows")
    
    def __call__(self, *args):
        """
        Format search query
        attack_family: (collection OR credential_access)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'


@dataclass
class Products(QueryParamter):
    """
    Parameters:
        
    """
    label: str = "Products"
    value: str = "tenable_products_required"
    # Repeats for each parameter option
    tenable_attack_surface_management: str = str("Tenable Attack Surface Management")
    tenable_identity_exposure: str = str("Tenable Identity Exposure")
    tenable_cloud_security: str = str("Tenable Cloud Security")
    tenable_vulnerability_management: str = str("Tenable Vulnerability Management")
    tenable_ot_security: str = str("Tenable OT Security")
    tenable_web_app_scanning: str = str("Tenable Web App Scanning")
    
    def __call__(self, *args):
        """
        Format search query
        attack_family: (collection OR credential_access)
        """
        query_str = " OR ".join([f'"{x}"' for x in args])
        return f'{self.value}:({query_str})'

