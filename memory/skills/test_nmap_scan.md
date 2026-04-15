---
name: test_nmap_scan
description: Auto-generated skill from successful pentest run
category: pentest
status: verified
trigger_pattern: test nmap scan
created_at: 2026-04-14T20:29:57.003080+00:00
source: reflect
---

# test_nmap_scan

## Commands Used

- `nmap -sV 192.168.1.1`
- `gobuster dir -u http://192.168.1.1`

## Findings

- Port 80 open (HTTP)
- Port 22 open (SSH)
- /admin found

## Notes

This skill was automatically captured from a successful run. Review and edit
before promoting to production use.
