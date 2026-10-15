# Compromised Windows Server 2022 (OU simulation): answer key

Dataset: "Compromised Windows Server 2022 (simulation)", Open University ORDO
(https://ordo.open.ac.uk/articles/dataset/Compromised_Windows_Server_2022_simulation_/26038642/1),
by Benjamin Donnachie, made for research on AI/ML post-breach triage. Everything in it (user names,
IP addresses) is synthetic. A small UK office network ran from September 2023 to February 2024; the
administrator enabled remote access for home working; on 12 February 2024 the server stopped
responding and showed ransomware. The disk was decrypted and imaged as E01.

**Held out.** The copilot's knowledge is not tuned on this image. Do not add facts from it to
prompts, tool descriptions or `copilot/knowledge_data/`.

**No key yet.** There is a walkthrough at iblue.team (CTF challenges, "Compromised Windows Server
2022 (simulation)", with pages on Plaso and Events Ripper): OS version, missing patches, exposed
services, weak passwords. When the facts are known, add them to `benchmark.yaml` with their source
here, and score saved runs again (no new run needed).

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
