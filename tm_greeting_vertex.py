#!/usr/bin/env python3

"""Greeting agent model that uses Vertex AI as the sole LLM provider.

This model represents a customer-facing greeting agent where all model
calls go through Vertex AI. It intentionally omits any local emulators.
"""

from pytm import TM, Boundary, Actor, Server, Dataflow, Datastore

tm = TM("Greeting Agent - Vertex AI Only")
tm.description = "Greeting agent where the LLM is accessed only via Vertex AI (cloud provider)."

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

# Secrets stored in Secret Manager (represented as a Datastore inside VPC)
secret_manager = Datastore("Secret Manager")
secret_manager.inBoundary = vpc
secret_manager.description = "Managed secrets, service account keys, API keys."

# Dataflows
Dataflow(user, root_agent, "User prompt (HTTPS/TLS)")
Dataflow(root_agent, vertex_ai, "LLM request to Vertex AI (authenticated, TLS)")
Dataflow(vertex_ai, root_agent, "LLM response (model output)")
Dataflow(root_agent, user, "Greeting response (TLS)")

# Secrets access
Dataflow(root_agent, secret_manager, "Reads service credentials (Secret Manager, least-privilege)")

if __name__ == "__main__":
    tm.process()
