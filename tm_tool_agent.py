"""
Tool-agent threat model (pytm).

Converted from the ADK reference example into a pytm model so you can
generate a DFD/PNG showing the agent's interaction with an external
search tool and local secrets.

Run to generate a DFD (and pipe to dot to render a PNG):
    python3 tm_tool_agent.py --dfd | dot -Tpng -o tm_tool_agent.png

Or just run
    python3 tm_tool_agent.py
which will call `tm.process()` and respect the CLI flags supported by pytm.
"""

from pytm import TM, Boundary, Actor, Server, Datastore, Dataflow


tm = TM("Tool Agent - Threat Model")
tm.description = "Threat model for a tool-using agent that calls external search APIs and stores API keys locally."

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud Services")
dev_machine = Boundary("Developer / Host Machine")

# Actors
user = Actor("User")
user.inBoundary = dev_machine

# Root agent (runs on developer machine or as an edge service)
root_agent = Server("Tool Agent (root)")
root_agent.description = "Root agent that can call external tools (e.g., google_search)."
root_agent.inBoundary = dev_machine
root_agent.controls.isHardened = True

# External tool / API (treated as an external server in the Internet boundary)
google_search_api = Server("Google Search API (external)")
google_search_api.inBoundary = internet

# Local secret store for API keys
secret_store = Datastore("Secrets / API Keys")
secret_store.inBoundary = dev_machine
secret_store.description = "Local secrets used by the agent (API keys, tokens)."

# Optional cloud-hosted agent engine (illustrates hybrid deployments)
cloud_llm = Server("Cloud LLM / Tool Engine")
cloud_llm.inBoundary = cloud

# Dataflows
Dataflow(user, root_agent, "User invokes agent (CLI / UI)")
Dataflow(root_agent, google_search_api, "Calls google_search API (tool call)")
Dataflow(google_search_api, root_agent, "Search results / response")
Dataflow(root_agent, secret_store, "Reads API key / credentials")
Dataflow(root_agent, cloud_llm, "Optional: call cloud engine")
Dataflow(cloud_llm, root_agent, "Optional: cloud response")


if __name__ == "__main__":
    tm.process()
