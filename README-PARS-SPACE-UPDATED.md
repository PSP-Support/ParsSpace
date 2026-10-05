# Pars Space updated build

## Added in this build
- Protocol-specific fields: only settings relevant to VLESS / VMess / Trojan / Reality are shown.
- Direct config output from the user builder. It returns the protocol link, not a subscription URL.
- Authenticated Linux terminal at `/api/terminal/exec`.
  - Uses `/bin/bash -lc` when available.
  - Runs as the panel service account.
  - No sudo/root escalation is added by the panel.
  - 30 second command timeout and 24 KB output cap.
  - Disable with `PARS_TERMINAL_ENABLED=0`.
- IP scanner UI using the existing authenticated TCP probe endpoint. Use only on infrastructure you own or are authorized to test.
- SNI scanner UI using `data/sni_reality_for_scan.txt`.
- Dedicated Pars Space subscription page at `/p/<uuid>` with live usage, connection count, direct profile links and copy actions.
- `/p/<uuid>` no longer depends on an external `public_page.py` module.

## SNI list
Create the file:

```bash
mkdir -p data && nano data/sni_reality_for_scan.txt
```

Put one hostname per line. Example:

```text
example.com
example.org
```

Comments beginning with `#` are ignored.

## Terminal
The terminal is intentionally authenticated. It accepts normal Linux shell syntax including pipes and redirects, but it is not an anonymous shell and does not add sudo/root escalation.

For a deployment where the service should not expose the terminal at all:

```bash
PARS_TERMINAL_ENABLED=0
```
