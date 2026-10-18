"""
AutoRelay — Defensive Remediation Knowledge Base and Mapping Engine.

Maps assessment findings (SMB signing, LDAP signing, LDAP channel binding,
coercion vectors, and reachability) to verified defensive remediation guidance.
Provides exact Windows Group Policy paths, registry settings, validation commands,
and official reference links.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional


@dataclass
class RemediationGuidance:
    """Structured defensive remediation guidance for a security finding."""
    issue: str
    why_it_matters: str
    potential_impact: str
    recommended_action: str
    gpo_path: Optional[str] = None
    registry_setting: Optional[str] = None
    validation_guidance: Optional[str] = None
    references: list[str] = field(default_factory=list)
    requires_verification: bool = False

    def format_remediation_summary(self) -> str:
        """Format a concise multi-line summary of the guidance."""
        lines = [self.recommended_action]
        if self.gpo_path:
            lines.append(f"GPO: {self.gpo_path}")
        if self.registry_setting:
            lines.append(f"Registry: {self.registry_setting}")
        if self.validation_guidance:
            lines.append(f"Validation: {self.validation_guidance}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        """Convert guidance into a plain dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Verified Defensive Remediation Catalog
# ---------------------------------------------------------------------------

REMEDIATION_CATALOG: dict[str, RemediationGuidance] = {
    "smb_signing_disabled": RemediationGuidance(
        issue="SMB signing is completely disabled on the target server.",
        why_it_matters=(
            "When SMB signing is disabled, network traffic between clients and the "
            "SMB server is transmitted without cryptographic integrity verification."
        ),
        potential_impact=(
            "Adversaries positioned on the local network segment can intercept, modify, "
            "or relay NTLM authentication to this server, gaining unauthorized access "
            "with the victim's privileges."
        ),
        recommended_action=(
            "Configure Group Policy to require SMB packet signing on all Windows servers "
            "and workstations."
        ),
        gpo_path=(
            "Computer Configuration > Windows Settings > Security Settings > "
            "Local Policies > Security Options > "
            "'Microsoft network server: Digitally sign communications (always)' = Enabled. "
            "Also configure 'Microsoft network client: Digitally sign communications (always)' = Enabled."
        ),
        registry_setting=(
            r"Path: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | "
            r"Value: RequireSecuritySignature (REG_DWORD) = 1, EnableSecuritySignature (REG_DWORD) = 1"
        ),
        validation_guidance=(
            "PowerShell: Get-SmbServerConfiguration | Select-Object EnableSecuritySignature, RequireSecuritySignature"
        ),
        references=[
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing",
            "https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security",
        ],
        requires_verification=False,
    ),

    "smb_signing_enabled_not_required": RemediationGuidance(
        issue="SMB signing is enabled but not required (optional).",
        why_it_matters=(
            "The server supports SMB signing but does not enforce it unless the client "
            "demands it. Attackers acting as an NTLM relay omit the signing request, "
            "allowing relayed sessions to succeed."
        ),
        potential_impact=(
            "Permits NTLM relay attacks against the server. If a privileged account's "
            "authentication is coerced or relayed, the attacker can execute code or access shares."
        ),
        recommended_action=(
            "Enforce SMB signing across all domain members, including member servers "
            "and file servers, not only Domain Controllers."
        ),
        gpo_path=(
            "Computer Configuration > Windows Settings > Security Settings > "
            "Local Policies > Security Options > "
            "'Microsoft network server: Digitally sign communications (always)' = Enabled"
        ),
        registry_setting=(
            r"Path: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | "
            r"Value: RequireSecuritySignature (REG_DWORD) = 1"
        ),
        validation_guidance=(
            "PowerShell: (Get-SmbServerConfiguration).RequireSecuritySignature -eq $True"
        ),
        references=[
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing",
            "https://techcommunity.microsoft.com/t5/storage-at-microsoft/smb-signing-required-by-default-in-windows-11/ba-p/3831704",
        ],
        requires_verification=False,
    ),

    "ldap_signing_not_enforced": RemediationGuidance(
        issue="LDAP signing is not enforced on the Domain Controller.",
        why_it_matters=(
            "Unsigned SASL/NTLM binds to LDAP are accepted without integrity protection, "
            "allowing relayed authentication directly to the directory service."
        ),
        potential_impact=(
            "Adversaries can relay coerced machine or user authentication to LDAP/LDAPS, "
            "creating rogue computer accounts, granting Resource-Based Constrained Delegation (RBCD), "
            "or performing DCSync attacks if the relayed account has directory privileges."
        ),
        recommended_action=(
            "Configure Domain Controllers to require LDAP server signing and channel binding. "
            "Test compatibility in staging first to identify legacy clients requiring updates."
        ),
        gpo_path=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Local Policies > Security Options > "
            "'Domain controller: LDAP server signing requirements' = Require signing"
        ),
        registry_setting=(
            r"Path: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters | "
            r"Value: LDAPServerIntegrity (REG_DWORD) = 2"
        ),
        validation_guidance=(
            "PowerShell: (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters').LDAPServerIntegrity -eq 2. "
            "Review Directory Services Event Log for Event IDs 2886 and 2887."
        ),
        references=[
            "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a",
            "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server",
        ],
        requires_verification=False,
    ),

    "ldap_channel_binding": RemediationGuidance(
        issue="LDAP channel binding tokens (CBT) are not strictly enforced.",
        why_it_matters=(
            "Without Channel Binding Tokens, an attacker can relay NTLM credentials over "
            "an outer TLS tunnel (LDAPS / port 636) without detection."
        ),
        potential_impact=(
            "Allows relay attacks targeting LDAPS even when TLS encryption is in place, "
            "bypassing signing protections if CBT is not enforced."
        ),
        recommended_action=(
            "Enforce LDAP Channel Binding Tokens on all Active Directory Domain Controllers."
        ),
        gpo_path=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "Local Policies > Security Options > "
            "'Domain controller: LDAP server channel binding token requirements' = Always"
        ),
        registry_setting=(
            r"Path: HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters | "
            r"Value: LdapEnforceChannelBinding (REG_DWORD) = 2"
        ),
        validation_guidance=(
            "PowerShell: (Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters').LdapEnforceChannelBinding -eq 2. "
            "Inspect Directory Services Event IDs 3039 and 3040."
        ),
        references=[
            "https://support.microsoft.com/en-us/topic/2020-ldap-channel-binding-and-ldap-signing-requirements-for-windows-ef185fb8-00f7-167d-744c-f299a66fc00a",
        ],
        requires_verification=False,
    ),

    "coercion_petitpotam": RemediationGuidance(
        issue="Encrypting File System Remote Protocol (MS-EFSR) interface detected.",
        why_it_matters=(
            "The EFSRPC interface can be abused via unauthenticated or authenticated RPC calls "
            "(e.g. EfsRpcOpenFileRaw) to coerce machine accounts into authenticating to arbitrary endpoints."
        ),
        potential_impact=(
            "Coerced Domain Controller machine account authentication can be relayed to Active Directory "
            "Certificate Services (AD CS) or other non-signing services, leading to full domain compromise."
        ),
        recommended_action=(
            "Apply Microsoft security update KB5005413 (CVE-2021-36942) and configure NETSH RPC filters "
            "to block unauthenticated EFSRPC calls, or disable the WebClient service."
        ),
        gpo_path=None,
        registry_setting=(
            r"Verify Microsoft KB5005413 patch level. "
            r"Optional: Block LSARPC/EFSRPC named pipes via RPC firewall rules if EFS is not utilized."
        ),
        validation_guidance=(
            "PowerShell: Get-HotFix -Id KB5005413. Confirm anonymous access to named pipes returns access denied."
        ),
        references=[
            "https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-466d-48d1-b640-ab2b21b157a3",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942",
        ],
        requires_verification=True,
    ),

    "coercion_printerbug": RemediationGuidance(
        issue="Print Spooler service (MS-RPRN) interface exposed.",
        why_it_matters=(
            "The Print Spooler RPC interface (pipe \\pipe\\spoolss) permits any domain user to trigger "
            "remote authentication via RpcRemoteFindFirstPrinterChangeNotificationEx."
        ),
        potential_impact=(
            "Domain Controllers running the Print Spooler service can be coerced into authenticating "
            "to attacker-controlled listeners and relayed to other services."
        ),
        recommended_action=(
            "Stop and disable the Print Spooler service on all Domain Controllers and critical infrastructure servers."
        ),
        gpo_path=(
            "Computer Configuration > Policies > Windows Settings > Security Settings > "
            "System Services > Print Spooler = Disabled"
        ),
        registry_setting=None,
        validation_guidance=(
            "PowerShell: Get-Service -Name Spooler | Select-Object Name, Status, StartType"
        ),
        references=[
            "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2010/ms10-061",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2010-2729",
        ],
        requires_verification=False,
    ),

    "coercion_shadowcoerce": RemediationGuidance(
        issue="File Server Remote VSS Protocol (MS-FSRVP) interface detected.",
        why_it_matters=(
            "MS-FSRVP (pipe \\pipe\\FssagentRpc) exposes backup shadow copy routines that can be "
            "instructed to authenticate against an arbitrary UNC path."
        ),
        potential_impact=(
            "Enables authentication coercion of the target server to a relay destination."
        ),
        recommended_action=(
            "Disable the 'File Server VSS Agent Service' feature and service on servers where "
            "Volume Shadow Copy backup over SMB is not strictly required."
        ),
        gpo_path=None,
        registry_setting=(
            r"Service: File Server VSS Agent Service (fssagent) set to Disabled"
        ),
        validation_guidance=(
            "PowerShell: Get-Service -Name 'fssagent' -ErrorAction SilentlyContinue | Select-Object Status, StartType"
        ),
        references=[
            "https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/fsrvp-overview",
            "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30154",
        ],
        requires_verification=True,
    ),

    "reachability_host_unreachable": RemediationGuidance(
        issue="Host is completely unreachable on tested assessment ports.",
        why_it_matters=(
            "Communication could not be established with the target host on core assessment ports."
        ),
        potential_impact=(
            "Target host is offline, host-isolated, or blocked by intervening network filtering."
        ),
        recommended_action=(
            "Verify host power state, network connectivity, routing, and firewall rules between "
            "the assessment station and the target."
        ),
        gpo_path=None,
        registry_setting=None,
        validation_guidance="Verify ICMP ping or TCP reachability on management ports.",
        references=[],
        requires_verification=False,
    ),

    "inconclusive_access_denied": RemediationGuidance(
        issue="Probe returned access denied when querying named pipe interface.",
        why_it_matters=(
            "Modern Windows environments restrict anonymous access to named pipes by default. "
            "The probe could not definitively confirm interface presence without authentication."
        ),
        potential_impact=(
            "The interface may still be vulnerable to coercion once an attacker obtains valid domain credentials."
        ),
        recommended_action=(
            "Verify interface existence and configuration using an authenticated administrative session "
            "or Group Policy audit. Ensure anonymous pipe restrictions remain enabled."
        ),
        gpo_path=(
            "Computer Configuration > Windows Settings > Security Settings > Local Policies > "
            "Security Options > 'Network access: Restrict anonymous access to Named Pipes and Shares' = Enabled"
        ),
        registry_setting=(
            r"Path: HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters | "
            r"Value: NullSessionPipes (REG_MULTI_SZ) should not contain spoolss, lsarpc, or efsrpc"
        ),
        validation_guidance=(
            "Inspect named pipes using Process Explorer or PowerShell from an elevated session on the target."
        ),
        references=[
            "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/network-access-restrict-anonymous-access-to-named-pipes-and-shares",
        ],
        requires_verification=True,
    ),
}


# ---------------------------------------------------------------------------
# Mapping and Lookup
# ---------------------------------------------------------------------------

def get_remediation_guidance(
    key_or_name: str,
    check_category: Optional[str] = None,
    detail: Optional[str] = None,
) -> Optional[RemediationGuidance]:
    """
    Look up remediation guidance based on check identifier, category, or detail.

    Args:
        key_or_name: Check or finding name (e.g. 'smb_signing.dc01', 'coercion_probe.petitpotam')
        check_category: Optional check category ('smb_signing', 'ldap_signing', etc.)
        detail: Optional detail string to refine lookup (e.g. 'DISABLED', 'access denied')

    Returns:
        RemediationGuidance instance if matched, otherwise None.
    """
    lowered_key = key_or_name.lower()
    lowered_cat = (check_category or "").lower()
    lowered_detail = (detail or "").lower()

    # Exact key match
    if lowered_key in REMEDIATION_CATALOG:
        return REMEDIATION_CATALOG[lowered_key]

    # SMB signing
    if "smb_signing" in lowered_key or lowered_cat == "smb_signing":
        if "disabled" in lowered_detail:
            return REMEDIATION_CATALOG["smb_signing_disabled"]
        return REMEDIATION_CATALOG["smb_signing_enabled_not_required"]

    # LDAP signing & channel binding
    if "ldap" in lowered_key or lowered_cat == "ldap_signing":
        if "channel_binding" in lowered_key or "channel" in lowered_detail:
            return REMEDIATION_CATALOG["ldap_channel_binding"]
        return REMEDIATION_CATALOG["ldap_signing_not_enforced"]

    # Coercion vectors
    if "petitpotam" in lowered_key or "efsrpc" in lowered_key:
        return REMEDIATION_CATALOG["coercion_petitpotam"]
    if "printerbug" in lowered_key or "spoolss" in lowered_key:
        return REMEDIATION_CATALOG["coercion_printerbug"]
    if "shadowcoerce" in lowered_key or "fsrvp" in lowered_key or "fssagent" in lowered_key:
        return REMEDIATION_CATALOG["coercion_shadowcoerce"]

    # Inconclusive / Denied
    if "denied" in lowered_detail or "access_denied" in lowered_detail:
        return REMEDIATION_CATALOG["inconclusive_access_denied"]

    # Reachability
    if "reachability" in lowered_key or lowered_cat == "reachability":
        if "not reachable" in lowered_detail or "unreachable" in lowered_detail:
            return REMEDIATION_CATALOG["reachability_host_unreachable"]

    return None


def register_remediation(key: str, guidance: RemediationGuidance) -> None:
    """Register custom remediation guidance in the catalog."""
    REMEDIATION_CATALOG[key.lower()] = guidance


def enrich_check_with_remediation(check: Any) -> None:
    """
    Enrich a preflight Check instance with defensive remediation guidance if empty.
    Preserves existing preflight report compatibility.
    """
    if getattr(check, "remediation", ""):
        return

    name = getattr(check, "name", "")
    category = getattr(check, "category", "")
    detail = getattr(check, "detail", "")

    guidance = get_remediation_guidance(name, check_category=category, detail=detail)
    if guidance:
        check.remediation = guidance.format_remediation_summary()
