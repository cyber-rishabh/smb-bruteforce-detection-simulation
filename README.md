# smb-bruteforce-detection-simulation
This project demonstrates detection and investigation of a simulated SMB brute-force authentication attempt in an isolated SOC lab environment.

## Environment
- Attacker: Kali Linux
- Victim: Windows 10
- SIEM Node: Ubuntu Server
- Network: VMware NAT (isolated)

## Tools & Telemetry
- Windows Security Logs
- Sysmon
- NXLog (centralized log forwarding)

## Use Case
Detect repeated failed SMB authentication attempts from a single source IP within a short time window.

## Outcome
- No successful compromise
- Detection validated via log correlation
- SOC-style incident report created

See `incident-report.md` for full analysis.
