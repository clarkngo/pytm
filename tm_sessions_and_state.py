#!/usr/bin/env python3
"""
Sessions & state threat model (pytm).

Converted from reference/5-sessions-and-state into a pytm model.
This model highlights a session service (session store) used by agents to
persist per-user state; it surfaces the attack surface for session poisoning,
unauthorized reads, and state leakage.

Run to emit a DOT DFD and pipe to dot to render a PNG:
    python3 tm_sessions_and_state.py --dfd | dot -Tpng -o tm_sessions_and_state.png

"""
from pytm import TM, Boundary, Actor, Server, Datastore, Dataflow


tm = TM("Sessions & State - Threat Model")
cm = tm
cm.description = "Agent architecture using a session service to persist per-user state (interaction history, preferences, purchases)."

# Boundaries
internet = Boundary("Internet")
org_network = Boundary("Organization Network")

# Actor
user = Actor("User")
user.inBoundary = org_network

# Root agent that manages Q&A and reads/writes session state
question_agent = Server("Question Answering Agent (root)")
question_agent.inBoundary = org_network
question_agent.controls.isHardened = True

# Session service / store
session_store = Datastore("Session Service (InMemory / Persistent)")
session_store.inBoundary = org_network
session_store.description = "Stores per-user state: user_name, user_preferences, interaction_history, etc."

# Optional external model / tool
genai_service = Server("GenAI Model (cloud)")
genai_service.inBoundary = internet

data_store = Datastore("User Data Store")
data_store.inBoundary = org_network

# Dataflows
Dataflow(user, question_agent, "User asks question / query")
Dataflow(question_agent, session_store, "Reads/Writes session state (preferences, history)")
Dataflow(question_agent, genai_service, "Calls GenAI model for answer")
Dataflow(genai_service, question_agent, "Model response")
Dataflow(question_agent, data_store, "Reads user profile data")
Dataflow(question_agent, session_store, "Appends interaction to history")

# Telemetry / logs
telemetry = Datastore("Telemetry / Logs")
telemetry.inBoundary = org_network
Dataflow(question_agent, telemetry, "Writes telemetry and audit logs")

if __name__ == "__main__":
    tm.process()
