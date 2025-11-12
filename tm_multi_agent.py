#!/usr/bin/env python3
"""
Multi-agent threat model (pytm).

Converted from the reference multi-agent ADK example into a pytm model.
Creates a manager agent that delegates to several sub-agents and shows
communications to external tools/APIs and shared stores (plan store, secrets).

Run to emit a DOT DFD and pipe to dot to render a PNG:
    python3 tm_multi_agent.py --dfd | dot -Tpng -o tm_multi_agent.png

"""
from pytm import TM, Boundary, Actor, Server, Datastore, Dataflow


tm = TM("Multi-Agent Manager - Threat Model")
tm.description = "Manager agent that delegates to multiple sub-agents and uses tools."

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud Services")
org_network = Boundary("Organization Network")

# Actors
user = Actor("User")
user.inBoundary = org_network

# Manager agent (could run in org network or cloud)
manager = Server("Manager Agent (root)")
manager.description = "Manager agent that delegates tasks to sub-agents and calls tools."
manager.inBoundary = org_network
manager.controls.isHardened = True

# Sub-agents - separate logical services that the manager delegates to
stock_analyst = Server("Stock Analyst (sub-agent)")
stock_analyst.inBoundary = cloud

funny_nerd = Server("Funny Nerd (sub-agent)")
funny_nerd.inBoundary = cloud

news_analyst = Server("News Analyst (tool)")
news_analyst.inBoundary = internet

# Shared services / stores
plan_store = Datastore("Plan Store")
plan_store.inBoundary = org_network
plan_store.description = "Shared plans and task artifacts used by agents."

secret_store = Datastore("Secrets / API Keys")
secret_store.inBoundary = org_network
secret_store.description = "API keys and credentials used to call external tools."

telemetry = Datastore("Telemetry / Logs")
telemetry.inBoundary = org_network
telemetry.description = "Telemetry and logs for agent actions and delegation decisions."

# Dataflows
Dataflow(user, manager, "User requests task / instruction")

# Manager delegating to sub-agents and tools
Dataflow(manager, stock_analyst, "Delegate: investment analysis")
Dataflow(manager, funny_nerd, "Delegate: content / humor generation")
Dataflow(manager, news_analyst, "Tool call: fetch news (AgentTool)")
Dataflow(news_analyst, manager, "News results")

# Sub-agents interacting with external services
Dataflow(stock_analyst, news_analyst, "Fetch market/news data")
Dataflow(stock_analyst, manager, "Analysis result")
Dataflow(funny_nerd, manager, "Generated content result")

# Shared stores access
Dataflow(manager, plan_store, "Writes task plans / orchestration")
Dataflow(stock_analyst, plan_store, "Reads/Writes analysis plans")
Dataflow(manager, secret_store, "Reads API keys")
Dataflow(stock_analyst, secret_store, "Reads API keys")
Dataflow(manager, telemetry, "Writes telemetry and decision logs")
Dataflow(stock_analyst, telemetry, "Writes analysis telemetry")

# Optional external cloud calls
# Represent a host/service inside the cloud boundary instead of using the
# Boundary object as a Dataflow endpoint (Boundary has no protocol attribute).
cloud_host = Server("Cloud Host")
cloud_host.inBoundary = cloud
Dataflow(manager, cloud_host, "Optional: manager hosted tasks")

if __name__ == "__main__":
    tm.process()
