# WAF Runner Setup (No SSH)

This repository uses a self-hosted GitHub Actions runner to deploy WAF changes on push to the `waf` branch.

## Live path

- Live repository path on WAF server: `/waf/saesac03_final_SOC`
- Live compose path: `/waf/saesac03_final_SOC/waf`

The workflow resets the live repository to `origin/waf` and applies `docker compose up -d` when the Compose plugin is available. It falls back to `docker-compose up -d` on hosts that still use the standalone binary.

## ModSecurity runtime settings

For the `owasp/modsecurity-crs:nginx` image, runtime ModSecurity settings are applied with `MODSEC_*` environment variables in `waf/docker-compose.yml`.

- `PARANOIA=2` by default
- `MODSEC_RULE_ENGINE=On` by default
- `MODSEC_REQ_BODY_ACCESS=On`
- `MODSEC_RESP_BODY_ACCESS=Off`
- `MODSEC_AUDIT_ENGINE=RelevantOnly`
- `MODSEC_AUDIT_LOG_FORMAT=JSON`

`waf/docker-compose.yml` now reads `PARANOIA` and `MODSEC_RULE_ENGINE` from environment variables, so `docker compose --env-file ./modes/<mode>.env up -d` applies the selected mode correctly. When no env file is supplied, the default runtime remains blocking mode with `PARANOIA=2`.

Do not bind-mount `waf/config/modsecurity.conf` into `/etc/modsecurity.d/modsecurity.conf` on the live container. This image family is designed to tune ModSecurity through environment variables and rule mounts, and direct replacement of the base ModSecurity config has caused container restart loops in this project before.

Project-specific pre-CRS rules live in `waf/rules/00_custom_rules.conf`. The compose file mounts that repo file into the container as `REQUEST-899-LOCAL-CUSTOM-BEFORE-CRS.conf`, which makes the load order explicit: local project rules first, then the stock CRS `REQUEST-901+` files.

This file is now reserved for false-positive tuning and scoped pre-CRS exceptions only. It does not add project-specific phase 2 attack blocking rules; CRS remains the blocking layer after the local tuning rules run.

Keep rule IDs unique across `waf/rules/00_custom_rules.conf` and any other local rule files. If the legacy `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` is reused later, do not mount it alongside `00_custom_rules.conf` until duplicate IDs are removed.

### Mode presets

Preset files are stored under `waf/modes/`:

- `block.env`: WAF blocking enabled
- `detect.env`: DetectionOnly, log without blocking
- `off.env`: ModSecurity engine off, reverse proxy only

All three presets keep `PARANOIA=2` for consistent CRS sensitivity; only `MODSEC_RULE_ENGINE` changes by mode.

### Effective rule load order

1. `REQUEST-899-LOCAL-CUSTOM-BEFORE-CRS.conf` from `waf/rules/00_custom_rules.conf`
2. CRS setup and stock CRS rule files (`REQUEST-901+`, `RESPONSE-*`)

With this structure, custom project rules get first pass on the transaction for scoped tuning and exclusions, and CRS still runs afterward as the primary blocking layer.

Run from `/waf/saesac03_final_SOC/waf`:

`docker compose --env-file ./modes/block.env up -d`

`docker compose --env-file ./modes/detect.env up -d`

`docker compose --env-file ./modes/off.env up -d`

If the host only has the legacy standalone binary, replace `docker compose` with `docker-compose`.

After mode changes, validate and reload:

`docker exec waf nginx -t`

`docker exec waf nginx -s reload`

## Runner requirements

1. Runner must be installed on the same server that runs Docker WAF.
2. Runner must have the `waf` label (workflow uses `runs-on: [self-hosted, waf]`).
3. Runner account must be able to run Docker commands.

## Docker permission options

Option A: Add runner user to the docker group.

```bash
sudo usermod -aG docker <runner_user>
```

After this, re-login or restart the runner service.

Option B: Allow Docker via sudoers (NOPASSWD).

Create `/etc/sudoers.d/runner-docker` and allow Docker commands for the runner user.

## Deployment flow

On `git push` to `waf` branch with changes under `waf/**` or `.github/workflows/nginx-reload.yml`, the workflow does:

1. `git fetch origin waf`
2. `git reset --hard origin/waf` in `/waf/saesac03_final_SOC`
3. `docker compose up -d` or `docker-compose up -d`
4. `docker exec waf nginx -t`
5. `docker exec waf nginx -s reload` (fallback: `kill -HUP 1`)

## SOC test traffic policy (DetectionOnly)

Use scoped test traffic so SOC logs are generated continuously without weakening production blocking.

1. Keep global blocking mode enabled: `SecRuleEngine On`.
2. Match all three test conditions in `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`:
   - Default tester source IP `127.0.0.1` (`REMOTE_ADDR`)
   - Dedicated header `X-SOC-Test: CHANGE_ME_SECRET`
   - Dedicated path `/soc-log-test`
3. Apply only to matched traffic: `ctl:ruleEngine=DetectionOnly`, `ctl:auditEngine=On`.
4. Keep exceptions narrow: one approved tester host, WAF ports 80/443 only.
5. If you need a remote tester instead of local loopback, replace the source IP in `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf` before deployment.

### Verification checklist

1. Push to the `waf` branch and confirm workflow success.
2. Send repetitive requests that match `/soc-log-test` and include the `X-SOC-Test` header.
3. Confirm WAF audit logs are created while ModSecurity does not block matched test traffic.
4. Confirm non-test traffic still uses normal blocking behavior.

## SOC test log generator script

Script path: `waf/scripts/generate_soc_test_traffic.py`

Example:

`python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5`

Notes:

- Set `--fixed-ip` if you need a constant `X-Forwarded-For` value in the generated requests.
- Omit `--fixed-ip` to rotate or randomize the forwarded IP values.

## Nginx JSON access log persistence

- Managed file: `waf/config/99-soc-json-log.conf`
- Compose mount: `./config/99-soc-json-log.conf:/etc/nginx/conf.d/99-soc-json-log.conf:ro`
- Duplicate prevention: `access_log off;` is set before `access_log /var/log/nginx/access.log soc_json;`

Apply sequence:

1. `docker compose up -d`
2. `docker exec waf nginx -t`
3. `docker exec waf nginx -s reload`

If the host only has the legacy standalone binary, replace `docker compose` with `docker-compose`.

## Board API method exception scope

- Scope is limited to `Host: kj.ac.kr` so the CRS method policy stays unchanged for other virtual hosts.
- PUT and DELETE are allowed only for `/api/board/posts/[id]` and `/api/board/posts/[postId]/comments/[commentId]`.
- OPTIONS is kept explicit for `/api/board/posts/*` preflight requests.
- Applied rule IDs: `990130`, `990131`, `990132`.
- These pre-CRS rules expand `tx.allowed_methods` for the scoped board paths, which prevents rule `911100` from raising anomaly score and avoids the follow-on `949110` 403 for normal board edit/delete traffic.

### Board API verification checklist

1. `PUT /api/board/posts/145` on `Host: kj.ac.kr` reaches the application and no longer logs rule `911100`.
2. `DELETE /api/board/posts/145/comments/10` on `Host: kj.ac.kr` reaches the application and no longer logs rule `911100`.
3. `OPTIONS` preflight requests for the same board paths succeed without WAF 403.
4. `PUT` or `DELETE` to non-board paths still trigger CRS method enforcement.
5. If a 403 remains after this change, review `942200` or other contributing rule hits in the same audit record as the next step.

## Search-route false-positive tuning scope

- `GET /api/board/posts`: excludes CRS inspection by attack tag for `ARGS:keyword` and `ARGS:author`.
- `GET /api/public/announcements`: excludes CRS inspection by attack tag for `ARGS:keyword`.
- Removed tags are limited to `attack-sqli`, `attack-xss`, `attack-rce`, and `attack-lfi`.
- `GET /api/public/academic-events` is intentionally not included because the current project scope does not use a search query on that route.
- This is a precision tradeoff: security-context strings such as `union select`, `/etc/passwd`, or `${jndi:...}` may pass through on the scoped search parameters, while the rest of CRS remains active for other paths and parameters.
