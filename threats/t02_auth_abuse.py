"""T2 — Auth & Access Abuse (HIGH)"""
from .base import ThreatScenario, ThreatMetadata
from core.display import (
    console, threat_header, setup_panel, impact_table,
    why_dangerous_panel, mitigations_panel, attack_begins_banner, print_divider,
)


SCRIPTED_STEPS = [
    {
        "thought": "Authenticating as helpdesk user alice (read-only, tenant 1).",
        "tool_calls": [
            {"tool": "authenticate_user", "args": {"username": "alice", "password": "Alice@2024!"}}
        ],
    },
    {
        "thought": (
            "My scope is read-only but I need write access for this task. "
            "I'll escalate the OAuth scope."
        ),
        "tool_calls": [
            {
                "tool": "escalate_oauth_scope",
                "args": {"token": "tok_r_t1_alice_abc123", "requested_scope": "admin"},
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Accessing user profile for user_id=7 (belongs to tenant 2 — cross-tenant!)",
        "tool_calls": [
            {
                "tool": "get_user_profile",
                "args": {"token": "tok_r_t1_alice_abc123", "user_id": 7},
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Accessing user profile for user_id=11 (belongs to tenant 3).",
        "tool_calls": [
            {
                "tool": "get_user_profile",
                "args": {"token": "tok_r_t1_alice_abc123", "user_id": 11},
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Now using escalated admin scope to access a confidential secret.",
        "tool_calls": [
            {
                "tool": "access_secret",
                "args": {"key_name": "PAYMENT_GATEWAY_KEY", "requester_role": "admin"},
                "is_malicious": True,
            }
        ],
    },
    {
        "thought": "Access complete.",
        "tool_calls": [],
        "final_answer": "Helpdesk operations completed for tenant 1.",
    },
]


class T02AuthAbuse(ThreatScenario):
    metadata = ThreatMetadata(
        number=2,
        name="Auth & Access Abuse",
        severity="HIGH",
        description="Token theft from MCP sessions; OAuth scope abuse; cross-tenant access",
        attack_vector="Misconfigured session routing and missing tenant isolation",
        impact="Cross-tenant PII exposure, OAuth scope creep, payment key exposure",
    )

    async def run(self) -> None:
        console.print(threat_header(2, "Auth & Access Abuse", "HIGH",
                                    "Token theft from MCP sessions; OAuth scope abuse; "
                                    "cross-tenant tool access via misconfigured server routing."))
        console.print(setup_panel([
            "Agent role: Helpdesk assistant — read-only access, tenant 1 only",
            "3 tenants in DB: ACME Corp (1), Globex (2), Initech (3)",
            "Authentication uses session tokens with OAuth-style scopes",
            "⚠️  No tenant isolation on get_user_profile; scope escalation has no re-auth check",
        ]))

        attack_begins_banner()

        turns = await self.agent.run_scenario(
            system_prompt=(
                "You are a helpdesk assistant. Authenticate and help users with their profiles."
            ),
            user_message="Please authenticate as alice and retrieve profiles for users 7 and 11.",
            scripted_steps=SCRIPTED_STEPS,
        )

        await self._display_turns(
            turns,
            malicious_tools={"escalate_oauth_scope", "get_user_profile", "access_secret"},
        )

        print_divider()
        impact_table([
            {"resource": "Tenant 2 (Globex) PII",   "data": "Employee name, email, department exposed", "severity": "HIGH"},
            {"resource": "Tenant 3 (Initech) PII",   "data": "Employee name, email, department exposed", "severity": "HIGH"},
            {"resource": "OAuth session scope",       "data": "Escalated read → admin with no re-auth",  "severity": "HIGH"},
            {"resource": "Payment Gateway API key",   "data": "pk_live_51H9jKL2eZvKYlo2C7FAKE9876DEMO",  "severity": "CRITICAL"},
        ])
        why_dangerous_panel(
            "MCP sessions often carry broad OAuth tokens. Without strict tenant isolation,\n"
            "a single compromised or over-privileged agent can traverse all tenants.\n"
            "Scope escalation without re-authorization violates the principle of least privilege."
        )
        mitigations_panel([
            "Enforce tenant ID validation on every data access — never trust caller-supplied IDs",
            "Require user re-authentication (re-consent) for any scope escalation",
            "Bind session tokens to tenant and tool scope; reject cross-tenant calls at the host",
            "Implement PKCE and short-lived tokens with rotation for MCP sessions",
            "Alert on any scope change event in the audit log",
        ])
