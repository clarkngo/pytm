#!/usr/bin/env python3

"""Local/dev posture threat model for an ADK agent.

This model is small and focused on developer-local risks: local .env secrets,
developer machine boundary, and a local LLM emulator. Use this when you're
testing or running an agent locally so the TM reflects the reduced attack
surface but higher chance of secret leakage from developer environments.
"""

from pytm import TM, Boundary, Actor, Server, Datastore, Dataflow, Lambda

tm = TM("Local ADK Agent - Developer Posture")
tm.description = "Threat model for running an ADK root agent on a developer machine (local/dev posture)."

# Boundaries
dev_machine = Boundary("Developer Machine (Local)")
local_network = Boundary("Local Network (LAN)")
internet = Boundary("Internet")

# Actors
developer = Actor("Developer")
developer.inBoundary = dev_machine

# Root agent running locally
root_agent = Server("GreetingAgent (local)")
root_agent.description = "Root agent instance running on a developer workstation for testing/debugging."
root_agent.inBoundary = dev_machine
root_agent.controls.isHardened = False

# Local LLM emulator or dev model runtime
local_llm = Server("Local LLM (emulator)")
local_llm.inBoundary = dev_machine

# Local secret store (e.g., .env or local keyfile)
local_secrets = Datastore("Local .env / keyfile")
local_secrets.inBoundary = dev_machine
local_secrets.description = "Developer secrets and API keys stored locally (high risk if committed)."

# Optional cloud dependencies (accessed from developer machine)
vertex_ai = Server("Vertex AI Agent Engine (cloud)")
vertex_ai.inBoundary = internet

# Dataflows (local interactions)
Dataflow(developer, root_agent, "Developer invokes agent (CLI / test harness)")
Dataflow(root_agent, local_llm, "Local model call (emulator)")
Dataflow(local_llm, root_agent, "Local model response")

# Local agent reading developer secrets
Dataflow(root_agent, local_secrets, "Reads API key / dev secrets (local .env)")

# Include optional cloud call to show hybrid dev-cloud interaction (developer may test against cloud)
Dataflow(root_agent, vertex_ai, "Optional: model API call to Vertex AI (for integration testing)")
Dataflow(vertex_ai, root_agent, "Optional: model output (integration)")

if __name__ == "__main__":
    tm.process()
