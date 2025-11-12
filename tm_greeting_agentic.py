#!/usr/bin/env python3

"""Greeting agent model extended with Agentic-AI threats context.

This model mirrors `tm_greeting_vertex.py` but adds elements and notes
that reflect common agentic AI threats (goal persistence, unintended
actions, privilege escalation, chained delegations, and data exfiltration).
Use this when you want your threat model to explicitly capture agentic
risks and mitigations.
"""

from pytm import TM, Boundary, Actor, Server, Dataflow, Datastore, Lambda, Finding

tm = TM("Greeting Agent - Vertex AI with Agentic-AI Threats Context")
tm.description = (
    "Greeting agent (customer-facing) where the LLM is Vertex AI and the model "
    "includes explicit components/notes for agentic-AI threats (delegation, "
    "persistence, action execution)."
)

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud Provider")
vpc = Boundary("VPC Service Perimeter")

# Actors
user = Actor("User")
user.inBoundary = internet

# Root agent hosted in cloud VPC (customer-facing)
root_agent = Server("GreetingAgent (root_agent)")
root_agent.description = "Customer-facing greeting agent; delegates reasoning to Vertex AI."
root_agent.inBoundary = vpc
root_agent.controls.isHardened = True
root_agent.controls.sanitizesInput = True

# Vertex AI as the sole LLM provider
vertex_ai = Server("Vertex AI Agent Engine")
vertex_ai.inBoundary = cloud

# Action Executor: an agentic capability that performs automated actions
# on behalf of the agent (e.g., API calls, email sends, bookings). This is
# high-risk in an agentic system and must be constrained by policy checks.
action_executor = Server("Action Executor")
action_executor.inBoundary = vpc
action_executor.description = (
    "Executes actions on downstream systems (APIs, payment providers, databases). "
    "Requires strict least-privilege IAM and approval/guardrails."
)

# Persistent state for agentic plans / goals (could be a DB or queue)
plan_store = Datastore("Plan Store (persistent state)")
plan_store.inBoundary = vpc
plan_store.description = "Stores agent plans, goals, and long-running task state. Potential for persistence of malicious goals."

# Model Armor / Policy Agent - enforces guardrails, policy checks, and human approval
policy_agent = Server("PolicyAgent (Guardrail)")
policy_agent.inBoundary = vpc
policy_agent.description = (
    "Validates proposed actions and long-running plans against company policy. "
    "Should enforce action whitelists, rate limits, and require human approvals for high-risk tasks."
)

# Secrets stored in Secret Manager (represented as a Datastore inside VPC)
secret_manager = Datastore("Secret Manager")
secret_manager.inBoundary = vpc
secret_manager.description = "Managed secrets, service account keys, API keys."

# Controls/Notes summarizing agentic-AI threats (attached to tm for quick reference)
tm.notes = (
    "Agentic-AI threats to consider:\n"
    "- Goal persistence: agents that store and pursue long-term goals may continue unintended actions.\n"
    "- Delegation & chaining: agents delegating to sub-agents can create complex multi-step attacks.\n"
    "- Action execution abuse: automated action performers can be abused to exfiltrate data or perform fraudulent transactions.\n"
    "- Privilege escalation: service accounts used by agents must be least-privilege.\n"
    "- Data exfiltration: model outputs may leak sensitive data; sanitize responses and block secrets."
)

# Dataflows (interactions)
d_user_root = Dataflow(user, root_agent, "User prompt (HTTPS/TLS)")

# Root agent consults Vertex AI
d_root_vertex = Dataflow(root_agent, vertex_ai, "LLM request to Vertex AI (authenticated, TLS)")
d_vertex_root = Dataflow(vertex_ai, root_agent, "LLM response (model output)")

# Root agent may propose an action; policy agent must validate
d_root_policy = Dataflow(root_agent, policy_agent, "Proposed action / plan (for validation)")
d_policy_root = Dataflow(policy_agent, root_agent, "Approval / rejection")

# If approved, root agent delegates to Action Executor
d_root_action = Dataflow(root_agent, action_executor, "Execute approved action (API call, booking)")
d_action_result = Dataflow(action_executor, root_agent, "Execution result / status")

# Action Executor or Root Agent may persist plans/state
d_root_plan_store = Dataflow(root_agent, plan_store, "Save plan / long-running task state")
d_action_plan_store = Dataflow(action_executor, plan_store, "Update task status / result")

# Secrets access must be least-privilege
d_root_secret = Dataflow(root_agent, secret_manager, "Read service credentials (Secret Manager, least-privilege)")

# Telemetry & logging (could be GCS/AlloyDB in a real deployment)
telemetry_store = Datastore("Telemetry / Audit Logs")
telemetry_store.inBoundary = vpc
telemetry_store.description = "Audit logs and telemetry for human-in-the-loop review and incident response."
d_policy_telemetry = Dataflow(policy_agent, telemetry_store, "Log policy decisions & flagged items")
d_root_telemetry = Dataflow(root_agent, telemetry_store, "Log executed actions & responses")

# Mitigations notes on key components
policy_agent.notes = (
    "Mitigations: enforce human approval for high-risk actions, rate-limit automated actions, validate destinations and inputs, and implement allowlists."
)
plan_store.notes = (
    "Mitigations: encrypt persisted plans, limit retention, and require explicit TTL; review stored goals periodically."
)
secret_manager.notes = (
    "Mitigations: use Secret Manager/KMS, rotate keys, audit access, grant minimal roles to action executor."
)

if __name__ == "__main__":
    # Add explicit Findings / overrides for common agentic-AI attack patterns.
    # Helper to find Threat objects loaded from threats.json
    def _find_threat(sid: str):
        for t in tm._threats:
            if t.id == sid:
                return t
        return None

    # Attach explicit findings (overrides) so these agentic threats show up
    # in reports even if automatic matching conditions differ.
    # Privilege escalation risk for action executor (AC12)
    t_ac12 = _find_threat("AC12")
    if t_ac12:
        action_executor.overrides.append(
            Finding(action_executor, id="F-AE-01", threat=t_ac12, response="mitigated", cvss="7.5")
        )

    # Privilege abuse risk for secret manager (AC01)
    t_ac01 = _find_threat("AC01")
    if t_ac01:
        secret_manager.overrides.append(
            Finding(secret_manager, id="F-SEC-01", threat=t_ac01, response="mitigated", cvss="9.0")
        )

    # Interception risk on LLM request dataflow (DE01) - ensure TLS/auth
    t_de01 = _find_threat("DE01")
    if t_de01:
        d_root_vertex.overrides.append(
            Finding(d_root_vertex, id="F-DF-01", threat=t_de01, response="mitigated", cvss="6.5")
        )

    # Resource consumption / flooding risk on policy agent (DO01)
    t_do01 = _find_threat("DO01")
    if t_do01:
        policy_agent.overrides.append(
            Finding(policy_agent, id="F-PA-01", threat=t_do01, response="mitigated", cvss="5.0")
        )

    # Process the model (resolve findings and optionally output diagrams/reports)
    tm.process()
