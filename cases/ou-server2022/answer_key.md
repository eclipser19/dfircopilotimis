# Compromised Windows Server 2022 (OU simulation): answer key

Dataset: "Compromised Windows Server 2022 (simulation)", Open University ORDO
(https://ordo.open.ac.uk/articles/dataset/Compromised_Windows_Server_2022_simulation_/26038642/1),
by Benjamin Donnachie, made for research on AI/ML post-breach triage. Everything in it (user names,
IP addresses) is synthetic. A small UK office network ran from September 2023 to February 2024; the
administrator enabled remote access for home working; on 12 February 2024 the server stopped
responding and showed ransomware. The disk was decrypted and imaged as E01.

**Held out.** The copilot's knowledge is not tuned on this image. Do not add facts from it to
prompts, tool descriptions or `copilot/knowledge_data/`.

Briefing (dataset description): "Simulated UK-based small office network running from Sept 2023 to
Feb 2024. The administrator opened RDP to facilitate working from home. As part of the scenario, on
12th Feb 2024 discovered the server was no longer responding with 'Red Petya' ransomware displayed on
the screen. Forensic experts were engaged, the disk decrypted and a forensic image taken in EnCase E01
format." The iblue.team pages about it are a tool tutorial (FTK Imager, Autopsy, Plaso, AXIOM), not
a solution.

**No key yet: there is no published solution.** Facts known from the briefing only (not scored,
since the agent is told them): RDP was opened by the administrator; the ransom screen said Red Petya;
discovered 12 Feb 2024.

## Building the key

The key must not come from the agent's own reasoning. Two independent sources:

1. **Detection rules, no agent involved.** In the Velociraptor GUI (as admin: these need the EXECVE
   permission the copilot's investigator role does not have), run `Server.Import.CuratedSigma` once
   (imports the curated Sigma / Hayabusa rule set from sigma.velocidex.com; the Velociraptor server
   needs internet), then collect the imported Hayabusa/Sigma artifact on this image's client. It
   evaluates the event logs inside Velociraptor (no external program, so it works on a dead disk).
   Export the hits (CSV) for the key.
2. **Checks of the agent's claims.** After a run, each claim becomes one collection or query to run
   in the GUI, with the evidence it should show. Confirmed claims become facts.

A fact goes into `benchmark.yaml` only when one of these confirms it; its source is noted below.
Facts the agent never mentioned can only come from source 1, so expect the first key to be partial.

## Setup

1. Download the E01 from ORDO and keep it **outside OneDrive** (e.g. `C:\evidence\ou-server2022\`).
2. Stop the Velociraptor client of the previous image (Ctrl+C), then:
   ```powershell
   .\velociraptor.exe deaddisk --add_windows_disk="C:\evidence\ou-server2022\<image>.E01" --hostname ou-image ou.yaml -v
   .\velociraptor.exe --config deaddisk_client.config.yaml --remap ou.yaml client -v
   ```
   `deaddisk` should log "Found Windows Partition". Keep `--hostname` neutral.
3. Check: collect `Windows.EventLogs.RDPAuth` in the GUI; it should return rows from 2023-2024.
4. Run: `python -m copilot.benchmark run cases/ou-server2022/benchmark.yaml --client C.<client id>`

## Questions and answers

| # | Question (benchmark id) | Answer | Source |
|---|---|---|---|
| | (to be filled) | | |
