# saesac03_final_SOC WAF

## Overview

- WAF operations repository for the SOC final project.
- Runs `owasp/modsecurity-crs:nginx` in Docker.
- Deploys through a self-hosted GitHub Actions runner on the `waf` branch.

## Repository Layout

- `waf/docker-compose.yml`: WAF service definition and runtime environment values.
- `waf/config/modsecurity.conf`: reference ModSecurity settings kept for parity with the compose environment.
- `waf/config/99-soc-json-log.conf`: JSON access log configuration.
- `waf/modes/*.env`: mode presets for block, detect, and off.
- `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`: runtime exclusions and pre-CRS overrides.
- `waf/rules/custom_rules.conf`: custom WAF detection rules and site-specific logging rules.
- `.github/workflows/nginx-reload.yml`: live deployment and reload workflow.
- `waf/scripts/generate_soc_test_traffic.py`: SOC test traffic generator.
- `docs/waf-runner-setup.md`: runner and deployment setup guide.

## Quick Start

1. Move to the `waf/` directory.
2. Start the stack with the mode preset you need:
   - `docker compose --env-file ./modes/block.env up -d`
   - `docker compose --env-file ./modes/detect.env up -d`
   - `docker compose --env-file ./modes/off.env up -d`
3. If your host only provides the standalone binary, replace `docker compose` with `docker-compose`.
4. Validate Nginx:
   - `docker exec waf nginx -t`
5. Reload Nginx:
   - `docker exec waf nginx -s reload`

## Deployment Flow

1. Push changes on the `waf` branch that touch `waf/**` or `.github/workflows/nginx-reload.yml`.
2. The self-hosted runner with label `waf` syncs `/waf/saesac03_final_SOC` to match `origin/waf`.
3. The workflow checks Docker permissions first, then runs `docker compose up -d` or `docker-compose up -d` through direct Docker access or `sudo`.
4. If `compose up` fails once, the workflow removes the `waf` container and retries with `--force-recreate`.
5. The workflow validates with `nginx -t` and reloads with `nginx -s reload`, falling back to `kill -HUP 1` if needed.
6. The workflow ends with `docker ps` and `docker logs --tail 30 waf` for a quick post-check.

## Runtime Notes

- Runtime ModSecurity settings are applied through `BACKEND`, `PARANOIA`, and `MODSEC_*` environment variables in `waf/docker-compose.yml`.
- Do not bind-mount `waf/config/modsecurity.conf` into the live container. This image family is tuned through environment variables and mounted rule files.
- `waf/modes/block.env`, `detect.env`, and `off.env` all keep `PARANOIA=2` and only change `MODSEC_RULE_ENGINE`.
- `waf/docker-compose.yml` removes rule `920350` at engine load time with `MODSEC_RULE_REMOVE_BY_ID=920350`.
- Runtime exclusions that must execute before CRS now live in `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`.
- JSON access logging is provided by `waf/config/99-soc-json-log.conf`.
- Typo-noise suppression is shared between URI/Referer filters in `99-soc-json-log.conf` and rule `920350` kill switches in `custom_rules.conf`.
- Board API method exceptions are limited to rule IDs `990130`, `990131`, and `990132`.

## SOC Test Traffic

- Detection-only SOC traffic is scoped to `/soc-log-test` with header `X-SOC-Test: CHANGE_ME_SECRET`.
- The current default rule also requires source IP `127.0.0.1` in `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`.
- If you need a remote tester host instead of local loopback, update that IP before deployment.
- The traffic generator runs sequential `normal`, `error`, and `waf` scenario groups and writes results to a JSONL file.
- Example traffic generator command:

`python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5`

- Optional flags:
  - `--repeat-per-scenario` changes how many times each scenario runs.
  - `--scenario-filter` runs only selected groups or scenario names.
  - `--host-header` sets an explicit Host header for virtual-host validation.
  - `--fixed-ip` sets a constant `X-Forwarded-For` value.
  - `--xff-list` provides the rotating `X-Forwarded-For` pool.
  - `--random-xff` randomizes the forwarded IP values.
  - `--insecure` skips TLS certificate validation for HTTPS testing.
  - `--result-file` changes the output filename.

## Additional Reference

For runner installation and live deployment details, see [docs/waf-runner-setup.md](docs/waf-runner-setup.md).
