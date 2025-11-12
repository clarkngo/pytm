#!/usr/bin/env python3
"""
Stateful multi-agent threat model (pytm).

Converted from reference/8-stateful-multi-agent into a pytm model.
This model shows a customer service manager agent that delegates to several
specialized sub-agents and maintains session state in a session store.

Run to emit a DOT DFD and pipe to dot to render a PNG:
    python3 tm_stateful_multi_agent.py --dfd | dot -Tpng -o tm_stateful_multi_agent.png

"""
from pytm import TM, Boundary, Actor, Server, Datastore, Dataflow


tm = TM("Stateful Multi-Agent - Customer Service")
cm = tm
cm.description = "Customer service manager that delegates to sub-agents and persists session state."

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud Services")
org_network = Boundary("Organization Network")

# Actor
user = Actor("User")
user.inBoundary = org_network

# Manager / root agent
customer_service = Server("Customer Service Agent (root)")
customer_service.description = "Primary customer service manager; routes queries and manages session state."
customer_service.inBoundary = org_network
customer_service.controls.isHardened = True

# Sub-agents
policy_agent = Server("Policy Agent (sub-agent)")
policy_agent.inBoundary = cloud

sales_agent = Server("Sales Agent (sub-agent)")
sales_agent.inBoundary = cloud

course_support_agent = Server("Course Support Agent (sub-agent)")
course_support_agent.inBoundary = cloud

order_agent = Server("Order Agent (sub-agent)")
order_agent.inBoundary = cloud

# External services/tools
payment_gateway = Server("Payment Gateway (external)")
payment_gateway.inBoundary = internet

# Stateful session store (represents InMemorySessionService or persistent store)
session_store = Datastore("Session Store")
session_store.inBoundary = org_network
session_store.description = "Per-user session state: interaction_history, purchased_courses, etc."

# Other shared stores
secret_store = Datastore("Secrets / API Keys")
secret_store.inBoundary = org_network

telemetry = Datastore("Telemetry / Logs")
telemetry.inBoundary = org_network

# Dataflows: user interaction
Dataflow(user, customer_service, "User query / request")

# Manager delegations and tool calls
Dataflow(customer_service, policy_agent, "Delegate: policy question")
Dataflow(customer_service, sales_agent, "Delegate: sales / purchase")
Dataflow(customer_service, course_support_agent, "Delegate: course support (only if purchased)")
Dataflow(customer_service, order_agent, "Delegate: order/refund inquiries")
Dataflow(customer_service, payment_gateway, "Calls payment gateway for purchases")
Dataflow(payment_gateway, customer_service, "Payment confirmation / response")

# Sub-agents responses
Dataflow(policy_agent, customer_service, "Policy response")
Dataflow(sales_agent, customer_service, "Sales / purchase result")
Dataflow(course_support_agent, customer_service, "Support content response")
Dataflow(order_agent, customer_service, "Order status / refund result")

# Session state and shared stores
Dataflow(customer_service, session_store, "Reads/Writes session state (interaction_history, purchased_courses)")
Dataflow(sales_agent, session_store, "Writes purchase to session state on success")
Dataflow(order_agent, session_store, "Reads purchase history for refunds")
Dataflow(customer_service, secret_store, "Reads API keys / tokens")
Dataflow(customer_service, telemetry, "Writes telemetry and audits")
Dataflow(policy_agent, telemetry, "Writes policy decision logs")

# Optional: sub-agents calling external news or content sources
news_api = Server("News API (external)")
news_api.inBoundary = internet
Dataflow(policy_agent, news_api, "Fetch news / context")
Dataflow(news_api, policy_agent, "News response")

if __name__ == "__main__":
    tm.process()
