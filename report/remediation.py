"""
AutoRelay — centralized remediation mappings.

This module maps finding types to concrete, actionable fixes. It is the
single source of truth for the "how to fix this" section of the report.

Design:
  - Keys are finding identifiers (category + check name without the host).
  - Values are Markdown-formatted remediation instructions.
  - The check modules no longer need to embed long remediation strings;
    they just emit the finding, and this module provides the fix.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Remediation dictionary
# ---------------------------------------------------------------------------
# Key format: "<category>.<check_suffix>"
# For host-specific checks, use the category and the vector/state name.
# For generic checks, use the category and a generic state.
#
# The `findings.py` module will call get_remediation() to look up the
# right string based on the Check's name and category.

REMEDIATIONS: dict[str, str] = {

    # --- SMB Signing ---------------------------------------------------
    "smb_signing.required": (
        "This is the secure configuration. No action needed. "
        "Consider relay-to-LDAP or another relay target."
    ),
    "smb_signing.enabled": (
        "**Enforce SMB signing via Group Policy:**\n"
        "1. Open Group Policy Management Console (GPMC).\n"
        "2. Edit the Default Domain Controllers Policy.\n"
        "3. Navigate to: Computer Configuration > Policies > Windows Settings > "
        "Security Settings > Local Policies > Security Options.\n"
        "4. Set **Microsoft network server: Digitally sign communications (always)** to Enabled.\n"
        "5. Set **Microsoft network client: Digitally sign communications (always)** to Enabled.\n"
        "6. Run `gpupdate /force` on domain controllers and member servers."
    ),
    "smb_signing.disabled": (
        "SMB signing is completely disabled, which is a critical finding "
        "independent of this assessment.\n\n"
        "**Enforce SMB signing immediately:**\n"
        "1. Apply the GPO settings for both server and client (see 'enabled' remediation).\n"
        "2. Monitor for unsigned SMB traffic to identify legacy clients that will break."
    ),
    "smb_signing.unknown": (
        "The tool could not determine the SMB signing state. "
        "Verify manually by running `nmap --script smb2-security-mode -p 445 <host>` "
        "or checking the host's local security policy / GPO."
    ),

    # --- LDAP Signing / Channel Binding ---------------------------------
    "ldap_signing.required": (
        "This is the secure configuration. No action needed."
    ),
    "ldap_signing.not_required": (
        "**Enforce LDAP signing and channel binding via Group Policy:**\n"
        "1. Edit the Default Domain Controllers Policy.\n"
        "2. Navigate to: Computer Configuration > Policies > Windows Settings > "
        "Security Settings > Local Policies > Security Options.\n"
        "3. Set **Domain controller: LDAP server signing requirements** to Require signing.\n"
        "4. Set **Domain controller: LDAP server channel binding token requirements** to Always.\n"
        "5. Run `gpupdate /force` on domain controllers.\n\n"
        "*Note: Enforce this carefully. Legacy applications that do not support "
        "LDAP signing or channel binding will break. Test in audit mode first.*"
    ),
    "ldap_signing.unknown": (
        "The tool could not determine the LDAP signing state from an anonymous rootDSE read. "
        "This is expected on modern Windows Server DCs.\n\n"
        "**Verify manually on the DC:**\n"
        "1. Open Registry Editor (`regedit`).\n"
        "2. Navigate to `HKLM\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters`.\n"
        "3. Check `LDAPServerIntegrity`. Value `1` = signing required; `0` = not required.\n"
        "4. Check `LdapEnforceChannelBinding`. Value `2` = always; `0` = never."
    ),

    # --- Coercion Probe -------------------------------------------------
    "coercion_probe.petitpotam": (
        "**Mitigate PetitPotam (MS-EFSRPC):**\n"
        "1. Apply the November 2021 security updates (KB5005413 and related) to all DCs.\n"
        "2. Disable NTLM authentication on Domain Controllers where feasible.\n"
        "3. Enable Extended Protection for Authentication (EPA) on AD CS endpoints."
    ),
    "coercion_probe.dfscoerce": (
        "**Mitigate DFScoerce (MS-DFSNM):**\n"
        "1. Microsoft has not released a direct patch; MS-DFSNM is exposed by design.\n"
        "2. Mitigate by disabling NTLM on DCs.\n"
        "3. Enforce SMB signing and LDAP signing across the domain.\n"
        "4. Monitor for unexpected machine-account authentications to attacker-controlled hosts."
    ),
    "coercion_probe.printerbug": (
        "**Mitigate PrinterBug (MS-RPRN):**\n"
        "1. Disable the Print Spooler service on Domain Controllers and other non-print-server hosts:\n"
        "   `Stop-Service -Name Spooler -Force`\n"
        "   `Set-Service -Name Spooler -StartupType Disabled`\n"
        "2. Apply Microsoft guidance for restricting spooler exposure."
    ),
    "coercion_probe.denied": (
        "The probe could not determine if the interface is available because "
        "Windows denied anonymous access to the named pipe.\n\n"
        "This is expected behavior on a hardened DC. It does **not** mean the "
        "interface is missing. To test if the interface is actually available, "
        "run the probe from an authenticated session (Stage 4)."
    ),
    "coercion_probe.unavailable": (
        "The interface is not registered on this host. If this is a DC and "
        "the interface is expected to be present (e.g., PetitPotam), verify "
        "that the relevant service or patch has not removed it unexpectedly."
    ),
}


def get_remediation(category: str, check_name: str, state: str) -> str:
    """
    Look up the remediation text for a given finding.

    Args:
        category:   The check category (e.g., "smb_signing").
        check_name: The check name (e.g., "smb_signing.192.168.1.10").
        state:      The derived state (e.g., "required", "enabled", "denied").

    Returns:
        Markdown-formatted remediation string. If no specific match is
        found, returns a generic fallback.
    """
    # Try specific first: "category.vector" (for coercion_probe)
    if category == "coercion_probe":
        # Extract vector name from check_name (e.g., "coercion_probe.host.petitpotam")
        parts = check_name.split(".")
        if len(parts) >= 3:
            vector = parts[-1]
            key = f"{category}.{vector}"
            if key in REMEDIATIONS:
                return REMEDIATIONS[key]

    # Try state-based: "category.state"
    key = f"{category}.{state}"
    if key in REMEDIATIONS:
        return REMEDIATIONS[key]

    # Fallback
    return "No specific remediation available. Review the finding details and consult the appropriate system documentation."
