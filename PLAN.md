# DFIR Copilot: Development Plan

This document tracks the roadmap for building a robust, LLM-driven Digital Forensics and Incident Response (DFIR) Copilot powered by Velociraptor and OpenAI (via LangChain).

## Core Philosophy
- **Dead-Disk First:** Analysis runs against mounted forensic images (E01, RAW, VHDX) natively using Velociraptor's remapping capabilities.
- **Database-Backed Memory:** Raw artifact logs are too large for LLM context windows. Artifacts are parsed and normalized into a local SQLite/DuckDB database. The LLM queries this database.
- **Reporting by Design:** The end goal is a structured, evidence-backed DFIR report (Executive Summary, Timeline, Correlations, IOCs). The agent uses a `record_finding` tool to build this report iteratively, ensuring evidence is never lost.

---

## Phase 0: Robust Foundation
**Goal:** Fix critical bugs in the current script (string injection, silent errors) and structure the code professionally.

- [x] **Refactor `run_vql`:** Pass parameters safely using the `VQLEnv` protobuf array to prevent VQL injection (e.g., paths with quotes crashing the query).
- [x] **Error Handling:** Read and return `response.log` from the gRPC stream. If a query fails, the LLM must see the actual Velociraptor error, not just an empty result.
- [x] **Modularization:** Split the monolith into a logical package structure (e.g., `client.py`, `tools.py`, `agent.py`).
- [x] **Agent Step Limits:** Impose a maximum iteration cap on the LangChain loop to prevent infinite tool-calling loops.

## Phase 1: Native Dead-Disk Integration
**Goal:** Stop relying on the LLM to manually rewrite file paths (which is brittle and fails constantly).

- [x] **Virtual Client Remapping:** Implement standard Velociraptor dead-disk analysis (`velociraptor deaddisk`). This mounts the image as a virtual client ID.
- [x] **Automated Inventory Check:** Before the LLM does anything, a startup script runs a baseline collection (OS version, hostname, available EVTX files, Registry hives) to ground the agent in reality.

## Phase 2: Normalized Database Timeline (The Core)
**Goal:** Fix the 50-record truncation limit and enable true time-window correlation without blowing up the LLM's context window.

- [x] **SQLite/DuckDB Integration:** Create a local case database.
- [x] **Collection to DB:** When the LLM requests an artifact (e.g., Prefetch), the script runs the VQL, parses the JSON, and stores it in the database.
- [x] **New LLM Tools:**
  - `query_timeline(start_time, end_time, filters)`
  - `search_iocs(keyword)`
  - `pivot_entity(user_or_process_name)`
- *Result:* The LLM analyzes aggregated SQL results rather than reading 50 raw JSON rows and guessing.

## Phase 3: Case Memory & Findings
**Goal:** Ensure the LLM remembers what it finds so it can write a complete report at the end.

- [x] **`record_finding` Tool:** A tool the LLM calls when it discovers something malicious. It logs: Timestamp, Description, Evidence Reference, Confidence, and MITRE Technique.
- [x] **Case Scope File:** A `case.yaml` file containing the initial prompt, known IOCs, and time scope to keep the agent focused.

## Phase 4: Report Generation
**Goal:** Output a professional DFIR report without relying on the LLM to format the entire Markdown document in one shot.

- [x] **Template Engine:** Use a Jinja2/Markdown template with rigid sections (Executive Summary, Scope, Timeline, Artifacts, Correlations).
- [x] **Final Agent Pass:** The agent writes the narrative summaries for each section based *only* on the database of findings recorded in Phase 3.
- [x] **Citations:** Every claim must reference a specific evidence row in the database.

## Phase 5: UI & Polish (Later)
- [x] Wrap the agent in a Streamlit chat interface.
- [x] Provide a sidebar for API keys, case database stats, and live findings.

---
**Status:** All phases complete! The DFIR Copilot is now a fully functional SQLite-backed agent with an interactive web UI.
