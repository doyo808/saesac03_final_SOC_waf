# AGENTS.md - Project Rules

## Project Scope
- This repository is for WAF operations only.
- Main targets:
  - waf/docker-compose.yml
  - waf/config/modsecurity.conf
  - waf/rules/custom_rules.conf
  - .github/workflows/nginx-reload.yml
  - docs/waf-runner-setup.md

## Shell Environment Rule CMD Required
- The execution shell is cmd, not PowerShell.
- Do not use PowerShell-only commands such as Get-ChildItem, Set-Content, or here-strings.
- Prefer cmd-safe commands: dir, type, findstr, copy, move, del.
- If advanced search is needed, use rg when available.

## Change Principles
- Keep changes minimal and production-safe.
- Prefer explicit, reversible edits.
- Do not change live host paths unless explicitly requested.

## Validation Checklist
- Rule edits must keep valid ModSecurity syntax.
- Deploy flow must remain: sync origin/waf, compose up, nginx -t, nginx reload.
- Update docs when behavior changes.

## Safety
- Never run destructive git commands unless explicitly requested.
- Never remove WAF rules without reason.
- Do not add unrelated application code.
