#!/usr/bin/env python3

# tm.py - Intelligent Travel Co. threat model example
from pytm import TM, Boundary, Actor, Server, Dataflow, Datastore, Lambda

tm = TM("Intelligent Travel Co. - Google ADK Agents")

# -------------------------
# Boundaries / Trust perimeters
# -------------------------
boundary_user_cloud = Boundary("User vs Cloud (Edge)")
boundary_cloud_external = Boundary("Cloud vs Third-Party APIs")
boundary_vpc = Boundary("VPC Service Perimeter (Internal Network)")
boundary_internal_tooling = Boundary("Agent vs Tool (Internal Segregation)")

# -------------------------
# Actors
# -------------------------
end_user = Actor("End-User (Traveler)")
end_user.inBoundary = boundary_user_cloud

developer = Actor("Developer/Admin")
# Developer/Admin manages cloud but typically interacts from outside; place them in cloud boundary for model purposes
developer.inBoundary = boundary_vpc

# -------------------------
# Cloud / Agent elements (hosted inside VPC perimeter)
# -------------------------
# Root & sub agents hosted on Cloud Run / Vertex AI Agent Engine
trip_coordinator = Server("TripCoordinator (Root Agent)")
trip_coordinator.description = "ADK Root agent that receives user goal and orchestrates sub-agents"
trip_coordinator.inBoundary = boundary_vpc

# ADK convention: expose the root agent using the name `root_agent` so examples
# and tooling that look for `root_agent` can find the primary agent entrypoint.
root_agent = trip_coordinator

flight_agent = Server("FlightAgent (Sub-Agent)")
flight_agent.description = "Searches/books flights; performs OAuth user-scoped API calls when needed"
flight_agent.inBoundary = boundary_vpc

hotel_agent = Server("HotelAgent (Sub-Agent)")
hotel_agent.description = "Searches/Books accommodations"
hotel_agent.inBoundary = boundary_vpc

policy_agent = Server("PolicyAgent (Guardrail Agent)")
policy_agent.description = "Checks requests/responses against company policy (approve/deny)"
policy_agent.inBoundary = boundary_vpc

# Infrastructure (represent as Servers / Services inside same VPC perimeter)
model_armor = Server("Model Armor (Edge Scanner)")
model_armor.description = "Scans incoming prompts/responses for prompt injection, PII, policy violations"
model_armor.inBoundary = boundary_vpc

cloud_run = Server("Google Cloud Run (host for agents)")
cloud_run.inBoundary = boundary_vpc

vertex_ai_engine = Server("Vertex AI Agent Engine")
vertex_ai_engine.inBoundary = boundary_vpc

# Basic ADK agent pattern: the root agent issues requests to an LLM provider
# and receives responses. Represent this interaction explicitly in the TM.
Dataflow(root_agent, vertex_ai_engine, "LLM request (model API call)")
Dataflow(vertex_ai_engine, root_agent, "LLM response (model output)")

google_iam = Server("Google Cloud IAM")
google_iam.description = "Service accounts and IAM policies"
google_iam.inBoundary = boundary_vpc

# -------------------------
# Internal Tooling & Data stores
# -------------------------
internal_pricing_tool = Lambda("Internal Pricing Tool (Cloud Function)")
internal_pricing_tool.description = "Cloud Function used by agents to fetch partner discounts"
internal_pricing_tool.inBoundary = boundary_internal_tooling
# Note: the cloud function is logically inside the VPC perimeter, but we keep a
# distinct boundary for 'Agent vs Tool' and therefore do not overwrite the
# lambda's `inBoundary` value.

alloydb = Datastore("AlloyDB Database")
alloydb.description = "User profiles, booking history, partner discount tables"
alloydb.inBoundary = boundary_vpc

gcs_bucket = Datastore("GCS Bucket (Session logs, uploads)")
gcs_bucket.description = "Persistent session history, conversation logs, uploaded documents"
gcs_bucket.inBoundary = boundary_vpc

# -------------------------
# External Third-Party APIs (outside Cloud)
# -------------------------
google_calendar_api = Server("Google Calendar API")
google_calendar_api.inBoundary = boundary_cloud_external

stripe_api = Server("Stripe Payment API")
stripe_api.inBoundary = boundary_cloud_external

external_flight_aggregator = Server("External Flight Aggregator API")
external_flight_aggregator.inBoundary = boundary_cloud_external

# -------------------------
# Dataflows (interactions)
# -------------------------
# 1. End-User -> Edge scanner (Model Armor) -> TripCoordinator
Dataflow(end_user, model_armor, "User request (text/audio) — TLS")
Dataflow(model_armor, trip_coordinator, "Sanitized request after prompt-injection & PII checks")

# 2. TripCoordinator -> FlightAgent (A2A delegation)
Dataflow(trip_coordinator, flight_agent, "A2A: 'Book flight to Paris next Tue' (delegation + context)")

# 3. FlightAgent -> PolicyAgent (guardrail check)
Dataflow(flight_agent, policy_agent, "Policy check: booking constraints (e.g., cost < $5,000)")

# 4. FlightAgent -> Internal Pricing Tool (Cloud Function)
Dataflow(flight_agent, internal_pricing_tool, "Invoke pricing tool to query partner discounts (service-account auth)")

# 5. Internal Pricing Tool -> AlloyDB
Dataflow(internal_pricing_tool, alloydb, "Query partner discount tables (read-only)")

# 6. FlightAgent -> Google Calendar API (OAuth / user-authorized)
Dataflow(flight_agent, google_calendar_api,
         "OAuth 2.0 flow: request user's consent; then use user-scoped token to read calendar (user-auth)")

# 7. FlightAgent -> External Flight Aggregator (agent-auth / API key)
Dataflow(flight_agent, external_flight_aggregator, "Search flights (agent service API key)")

# 8. FlightAgent & HotelAgent -> Stripe (payments)
Dataflow(flight_agent, stripe_api, "Process payment (tokenized payment method via Stripe; agent uses own API key)")
Dataflow(hotel_agent, stripe_api, "Process payment (agent uses own API key)")

# 9. FlightAgent -> GCS (session logs)
Dataflow(flight_agent, gcs_bucket, "Save search results & session state (logs, user uploads)")

# 10. TripCoordinator -> End-User (stream results)
Dataflow(trip_coordinator, end_user, "Stream flight options / booking confirmation to user (TLS)")

# 11. Developer/Admin -> Google IAM (manage service accounts & roles)
Dataflow(developer, google_iam, "Manage service accounts, IAM roles, and key rotation")

# 12. Model Armor <-> PolicyAgent (optional internal telemetry)
Dataflow(model_armor, policy_agent, "Telemetry: flagged prompts & policy rulings (for audit)")

# -------------------------
# Notes / Controls (attributes on elements; helpful for analysis)
# -------------------------
# Example: indicate least-privilege service account use
google_iam.notes = (
    "Service accounts used:\n"
    "- Agent service accounts (least-privilege; Cloud Function Invoker only for pricing tool)\n"
    "- Separate API keys for third-party APIs stored in Secret Manager\n"
)

model_armor.notes = "Enforces prompt injection detection, PII redaction, rate-limit/DoS protections at ingress."

internal_pricing_tool.notes = (
    "Runs with a dedicated service account with read-only access to AlloyDB. "
    "Sandboxed execution; validates and sanitizes inputs to prevent SQL injection."
)

# Mark important trust boundaries in the TM description (human-readable)
boundary_user_cloud.notes = "Edge boundary: MITM, prompt injection, unauthenticated requests. Controls: TLS, auth, Model Armor."
boundary_cloud_external.notes = "Agent -> Third-party external APIs. Controls: Secret Manager, per-service API keys, rate limiting."
boundary_vpc.notes = "VPC Service Controls enforce that only specific Cloud Run services can access AlloyDB and GCS."
boundary_internal_tooling.notes = "Cloud Function runs as separate service account; limited privileges to reduce blast radius."

# End of model
if __name__ == "__main__":
    tm.process()