# saesac03_final_SOC WAF

## Overview

- WAF operations repository for the SOC final project.
- Runs `owasp/modsecurity-crs:nginx` in Docker.
- Deploys through a self-hosted GitHub Actions runner on the `waf` branch.

## Repository Layout

- `waf/docker-compose.yml`: WAF service definition and runtime environment values.
- `waf/config/modsecurity.conf`: reference ModSecurity settings kept for parity with the compose environment.
- `waf/config/99-soc-json-log.conf`: JSON access log configuration.
- `waf/rules/custom_rules.conf`: custom WAF rules and scoped rule exceptions.
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

1. Push changes to the `waf` branch.
2. The root workflow `.github/workflows/nginx-reload.yml` syncs `/waf/saesac03_final_SOC` on the WAF server.
3. The workflow prefers `docker compose up -d` and falls back to `docker-compose up -d` when needed.
4. The workflow validates the Nginx config and reloads the running container.

## Runtime Notes

- Runtime ModSecurity settings are applied with `MODSEC_*` environment variables in `waf/docker-compose.yml`.
- Do not bind-mount `waf/config/modsecurity.conf` into the live container. This image family is tuned through environment variables and mounted rule files.
- JSON access logging is provided by `waf/config/99-soc-json-log.conf`.
- Board API method exceptions are limited to rule IDs `990130`, `990131`, and `990132`.

## SOC Test Traffic

- Detection-only SOC traffic is scoped to `/soc-log-test` with header `X-SOC-Test: CHANGE_ME_SECRET`.
- The current default rule also requires source IP `127.0.0.1` in `waf/rules/custom_rules.conf`.
- If you need a remote tester host instead of local loopback, update that IP before deployment.
- Example traffic generator command:

`python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5`

- Optional flags:
  - `--fixed-ip` sets a constant `X-Forwarded-For` value.
  - `--random-xff` randomizes the forwarded IP values.

## Additional Reference

For runner installation and live deployment details, see [docs/waf-runner-setup.md](docs/waf-runner-setup.md).
