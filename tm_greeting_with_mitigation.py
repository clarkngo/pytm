#!/usr/bin/env python3

"""A minimal pytm model that matches the basic ADK agent architecture.

This file provides a compact threat model with a single `root_agent`
that issues requests to an LLM provider (Vertex AI) and returns responses
to an end user.

This version is EXTENDED to include mitigation components for common
OWASP LLM threats.
"""

from pytm import TM, Boundary, Actor, Server, Dataflow

tm = TM("Basic ADK Agent - Greeting Agent (with Mitigations)")
tm.description = "Minimal threat model representing a single ADK root agent interacting with an LLM provider, now including security controls."

# Boundaries
internet = Boundary("Internet")
cloud = Boundary("Cloud Provider")
vpc = Boundary("VPC Service Perimeter")

# Actors
user = Actor("User")
user.inBoundary = internet

# Root agent (ADK expects a `root_agent` variable in examples)
root_agent = Server("GreetingAgent (root_agent)")
root_agent.description = "Simple greeting agent following ADK conventions."
root_agent.inBoundary = vpc

# LLM provider / model runtime
vertex_ai = Server("Vertex AI Agent Engine")
vertex_ai.inBoundary = cloud

# --- NEW MITIGATION COMPONENTS ---

rate_limiter = Server("Rate Limiter (WAF/Gateway)")
rate_limiter.description = "Mitigates LLM04 (Model DoS) by controlling request volume and size before they hit the agent."
rate_limiter.inBoundary = vpc  # Often on the edge of the VPC

output_sanitizer = Server("Output Sanitizer")
output_sanitizer.description = "Mitigates LLM02 (Insecure Output Handling) by stripping malicious content (e.g., <script> tags) before responding to the user."
output_sanitizer.inBoundary = vpc

# --- UPDATED DATAFLOWS ---

# 1. Ingress path (User to Agent) is now intercepted
Dataflow(user, rate_limiter, "User prompt (HTTP/TLS)")
Dataflow(rate_limiter, root_agent, "Throttled & validated prompt")

# 2. Internal agent <-> LLM flow (unchanged)
Dataflow(root_agent, vertex_ai, "LLM request (model API call)")
Dataflow(vertex_ai, root_agent, "LLM response (model output)")

# 3. Egress path (Agent to User) is now intercepted
Dataflow(root_agent, output_sanitizer, "Raw greeting response")
Dataflow(output_sanitizer, user, "Sanitized greeting response (TLS)")

if __name__ == "__main__":
    tm.process()