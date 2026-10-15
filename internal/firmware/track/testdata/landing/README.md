The first check of a box that has just landed on 26.7 and been re-pinned, as the lab proof of the
26.1 to 26.7 hop read it.

- `hop-b-check.json` is the raw result of the second hop, the only raw result the proof kept: the
  agent's own record (`os-netdefense-dev 1.24_0`, installed from the old ABI) and the core's
  "Vital flag changed" entry come back as two same-version reinstalls.
- `hop-a-check.json` is hand-built from what the first hop's run kept (a summary of the check and
  the status read, not the raw JSON): one reinstall, the agent's, with status `update`.

Both end `planNothingNewer` with the entries counted: a same-version reinstall holds nothing.
