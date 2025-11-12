#!/usr/bin/env python3

"""A minimal pytm model that matches the basic ADK agent architecture.

This file provides a compact threat model with a single `root_agent`
that issues requests to an LLM provider (Vertex AI) and returns responses
to an end user. It's intentionally small so it can be used as a template
for basic ADK agent threat modeling.
"""

from pytm import TM, Boundary, Actor, Server, Dataflow

tm = TM("Basic ADK Agent - Greeting Agent")
tm.description = "Minimal threat model representing a single ADK root agent interacting with an LLM provider."

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

# Dataflows
Dataflow(user, root_agent, "User prompt (HTTP/TLS)")
Dataflow(root_agent, vertex_ai, "LLM request (model API call)")
Dataflow(vertex_ai, root_agent, "LLM response (model output)")
Dataflow(root_agent, user, "Greeting response (TLS)")

if __name__ == "__main__":
    tm.process()
