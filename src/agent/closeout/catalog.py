"""Compiled Function 13 inventory, proof requirements and safe operator guidance.

Only validated local IDs can accompany these literal command recipes. Nothing executes them.
"""

from agent.evidence import CRITERIA

from .models import ROLES, SCENARIOS, require

# Stable obligations describe independent proofs, not status strings copied from reports.
RULES = {
    "UC1-01": ("deployed-secret-scan", "adapter-isolation"),
    "UC1-02": ("signed-obo-rar", "scoped-issuance", "lease-ttl", "sql-read", "exact-revoke"),
    "UC1-03": ("read-grants", "sql-read", "sql-write-denied"),
    "UC1-04": ("vault-policy-denied", "zero-issuance", "no-permission-group"),
    "UC1-05": ("vault-human-actor-audit",),
    "UC2-01": ("child-read", "parent-write", "lineage-audit"),
    "UC2-02": ("approval-before-issue", "denied-zero-issue", "timeout-zero-issue"),
    "UC2-03": ("complete-audit-index", "customer-receipt"),
    "UC3-01": ("exact-revoke", "same-jwt-invalid"),
    "UC3-02": ("native-user-risk", "automatic-session-revoke", "user-suspended", "teams-received"),
    "UC3-03": ("native-secret-detection", "automatic-secret-cleanup", "generation-after-check"),
    "UC3-04": ("native-trigger", "native-revocation-timing"),
    "UC4-01": (
        "independent-bootstrap",
        "native-svid",
        "independent-relying",
        "entity-ceiling-binding",
    ),
    "UC4-02": ("inside-ceiling", "outside-ceiling"),
    "UC4-03": ("absent-before", "native-discovery", "notification-before-enrollment"),
}
OWNERS = {
    "UC1-01": ["agent_engineering"],
    "UC1-02": ["verify_owner", "vault_owner"],
    "UC1-03": ["vault_owner"],
    "UC1-04": ["vault_owner", "verify_owner"],
    "UC1-05": ["vault_owner"],
    "UC2-01": ["agent_engineering", "verify_owner", "vault_owner"],
    "UC2-02": ["verify_owner", "agent_engineering"],
    "UC2-03": ["customer_security", "agent_engineering"],
    "UC3-01": ["vip_owner", "vault_owner", "verify_owner"],
    "UC3-02": ["vip_owner", "verify_owner"],
    "UC3-03": ["vip_owner", "vault_owner"],
    "UC3-04": ["vip_owner", "agent_engineering"],
    "UC4-01": ["vault_owner", "verify_owner"],
    "UC4-02": ["vault_owner"],
    "UC4-03": ["vip_owner"],
}
BUILD_STORIES = {
    **{f"F13.{i:02}": ["US1", "US2"] for i in range(1, 8)},
    **{f"F13.{i:02}": ["US4"] for i in range(8, 11)},
    **{f"F13.{i:02}": ["US3"] for i in range(11, 14)},
}
TEST_CRITERIA = {
    "F13-T1": [c for c in CRITERIA if c.startswith(("UC1", "UC2"))],
    "F13-T2": [c for c in CRITERIA if c.startswith("UC3")],
    "F13-T3": [c for c in CRITERIA if c.startswith("UC4")],
    "F13-T4": list(CRITERIA),
    "F13-T5": [],
    "F13-T6": [],
}


def catalog():
    """Return exact compiled identities for every design and review obligation."""
    return {
        "build": list(BUILD_STORIES),
        "tests": list(TEST_CRITERIA),
        "gates": [f"P4-G{i}" for i in range(1, 6)],
        "criteria": list(CRITERIA),
        "use_cases": [f"UC{i}" for i in range(1, 5)],
        "experiments": list(SCENARIOS),
        "roles": list(ROLES),
    }


def guide(selector=None):
    """Return concrete, literal steps and honest missing-proof actions without dispatch."""
    require(selector is None or selector in (*SCENARIOS, "UC1", "UC2", "UC3", "UC4"))
    guides = {
        "UC1": {
            "owner": "vault_owner",
            "commands": [
                {
                    "command": "agent validate ready --suite live-database",
                    "effect": "local-inspection",
                },
                {
                    "command": "agent validate run --suite live-database --mode live",
                    "effect": "credential-issuance-and-revoke",
                },
            ],
            "capture": (
                "Capture signed human/actor OBO/RAR, exact lease/TTL/grants/SELECT"
                " and revoke, plus native Vault denial and audit."
            ),
            "blocker": (
                "Demo-tier audit unavailable: Vault owner supplies an entitled aud"
                "it export or obtains explicit customer/vendor exception agreement"
                "."
            ),
            "recheck": (
                "Recapture the database run; reassess UC1 proof. A local actor-onl"
                "y denial does not prove Vault denial."
            ),
            "cleanup": (
                "Use agent recover status and its exact incident revoke instructio"
                "ns; never clear uncertain leases."
            ),
        },
        "UC2": {
            "owner": "verify_owner",
            "commands": [
                {
                    "command": "agent validate ready --suite live-phone --scenario phone-approved",
                    "effect": "local-inspection",
                },
                {
                    "command": "agent validate ready --suite live-phone --scenario phone-denied",
                    "effect": "local-inspection",
                },
                {
                    "command": (
                        "agent validate run --suite live-phone --scenario phone-approved -"
                        "-mode live --interactive"
                    ),
                    "effect": "phone-prompt",
                },
                {
                    "command": (
                        "agent validate run --suite live-phone --scenario phone-denied --m"
                        "ode live --interactive"
                    ),
                    "effect": "phone-prompt",
                },
            ],
            "capture": (
                "Use the existing workspace task flow for child Jira read and pare"
                "nt write; capture lineage, exact approval binding, denial/timeout"
                " zero issuance and audit receipt."
            ),
            "blocker": (
                "Verify owner repairs the registered-device denial flow with provi"
                "der support before a chosen fresh test; no automatic prompts."
            ),
            "recheck": (
                "Capture actual phone transaction and gated-effect evidence; phone"
                "-only checks do not prove a complete parent write."
            ),
            "cleanup": (
                "Inspect recovery status and exact outstanding cleanup; never repl"
                "ay the parent write."
            ),
        },
        "UC3": {
            "owner": "vip_owner",
            "commands": [
                {"command": "agent respond providers readiness", "effect": "local-inspection"},
                {
                    "command": "agent respond providers status --incident UUID",
                    "effect": "local-inspection",
                },
                {"command": "agent respond status --incident UUID", "effect": "local-inspection"},
            ],
            "capture": (
                "Follow specs/007-provider-remediation/quickstart.md for authorize"
                "d native event/probes; collect actual risk origin, each independe"
                "nt control, Teams receipt and bounded trigger-to-revocation timin"
                "g."
            ),
            "blocker": (
                "VIP owner supplies the reviewed event/collector schema and native"
                " remediation receipt. Policy denial is not JWT invalidation."
            ),
            "recheck": (
                "Recapture the exact incident promptly; all nine Function 10 paths"
                " retain their own proof/freshness rules."
            ),
            "cleanup": (
                "Follow agent respond status per-action repair instructions; do no"
                "t retry uncertain effects or remove holds."
            ),
        },
        "UC4": {
            "owner": "vault_owner",
            "commands": [
                {"command": "agent govern readiness --candidate UUID", "effect": "live-read"},
                {"command": "agent govern closeout --candidate UUID", "effect": "local-inspection"},
            ],
            "capture": (
                "Follow specs/008-shadow-agent-governance/quickstart.md: absence/a"
                "ctivity, VIP discovery, independent bootstrap/SVID verification a"
                "nd reviewed enrollment/ceiling proofs."
            ),
            "blocker": (
                "VIP/Vault owners supply real pre-registration discovery and entit"
                "led native identity/registry evidence."
            ),
            "recheck": (
                "Recapture the candidate's full proof history; a registered or loc"
                "ally held agent alone cannot pass UC4."
            ),
            "cleanup": (
                "Preserve uncertain credential/registration intents; use existing "
                "explicit evidence resolution, never delete registration to repeat"
                " a test."
            ),
        },
    }
    for scenario in SCENARIOS:
        guides[scenario] = {
            "owner": "vault_owner",
            "commands": [],
            "capture": (
                "Import pre-operation activity and entity/alias inventory, prepare"
                " the experiment, externally run 100 successful distinct operation"
                "s, then import exact roster/mappings and complete final export."
            ),
            "blocker": (
                "Verify/Vault/agent owners supply 100 genuine subjects for user sc"
                "enarios and the approved mode-specific test harness. Missing agen"
                "t-only/direct runner is execution_surface_unavailable; do not cha"
                "nge actor-only denial."
            ),
            "recheck": (
                "Obtain complete export after the owner-confirmed reporting delay;"
                " measure scoped scenario, reused and incremental client sets sepa"
                "rately."
            ),
            "documentation": (
                "https://developer.hashicorp.com/vault/api-docs/system/internal-counters"
            ),
            "cleanup": (
                "Follow the existing test harness's exact credential cleanup; pres"
                "erve evidence and unresolved issuance."
            ),
        }
    return guides[selector] if selector else guides
