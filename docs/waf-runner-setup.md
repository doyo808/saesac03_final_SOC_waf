# WAF Runner Setup (No SSH)

This repository uses a self-hosted GitHub Actions runner to deploy WAF changes on push to the `waf` branch.

## Live path

- Live repository path on WAF server: `/waf/saesac03_final_SOC`
- Live compose path: `/waf/saesac03_final_SOC/waf`

The workflow resets the live repository to `origin/waf` and applies `docker-compose up -d`.

## ModSecurity runtime settings

For the `owasp/modsecurity-crs:nginx` image, runtime ModSecurity settings are applied with `MODSEC_*` environment variables in `waf/docker-compose.yml`.

- `MODSEC_RULE_ENGINE=On`
- `MODSEC_REQ_BODY_ACCESS=On`
- `MODSEC_RESP_BODY_ACCESS=Off`
- `MODSEC_AUDIT_ENGINE=RelevantOnly`
- `MODSEC_AUDIT_LOG_FORMAT=JSON`

Do not bind-mount `waf/config/modsecurity.conf` into `/etc/modsecurity.d/modsecurity.conf` on the live container. This image family is designed to tune ModSecurity through environment variables and rule mounts, and direct replacement of the base ModSecurity config has caused container restart loops in this project before.

## Runner requirements

1. Runner must be installed on the same server that runs Docker WAF.
2. Runner must have the `waf` label (workflow uses `runs-on: [self-hosted, waf]`).
3. Runner account must be able to run Docker commands.

## Docker permission options

Option A: Add runner user to docker group

```bash
sudo usermod -aG docker <runner_user>
```

After this, re-login or restart runner service.

Option B: Allow docker via sudoers (NOPASSWD)

Create `/etc/sudoers.d/runner-docker` and allow docker commands for the runner user.

## Deployment flow

On `git push` to `waf` branch with changes under `waf/**`, workflow does:

1. `git fetch origin waf`
2. `git reset --hard origin/waf` in `/waf/saesac03_final_SOC`
3. `docker-compose up -d`
4. `docker exec waf nginx -t`
5. `docker exec waf nginx -s reload` (fallback: `kill -HUP 1`)

## SOC test traffic policy (DetectionOnly)

Use scoped test traffic so SOC logs are generated continuously without weakening production blocking.

1. Keep global blocking mode enabled: `SecRuleEngine On`.
2. Match all three test conditions in `waf/rules/custom_rules.conf`:
   - Fixed tester source IP (`REMOTE_ADDR`)
   - Dedicated header (`X-SOC-Test`)
   - Dedicated path (`/soc-log-test`)
3. Apply only to matched traffic: `ctl:ruleEngine=DetectionOnly`, `ctl:auditEngine=On`.
4. Keep firewall/pfSense exceptions narrow: one approved tester host, WAF ports 80/443 only.
5. Before deployment, replace placeholders: tester IP `192.168.10.50`, header secret `CHANGE_ME_SECRET`.

### Verification checklist

1. Push to `waf` branch and confirm workflow success.
2. Send repetitive requests from the tester host with path `/soc-log-test` and header `X-SOC-Test`.
3. Confirm WAF audit logs are created while ModSecurity does not block matched test traffic.
4. Confirm non-test traffic still uses normal blocking behavior.

## SOC test log generator script

Script path: `waf/scripts/generate_soc_test_traffic.py`

Example:
`python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5`

Notes: set `--fixed-ip` if you need a constant X-Forwarded-For value; omit it to randomize per request.
 
## Nginx JSON access log persistence 
 
- Managed file: `waf/config/99-soc-json-log.conf` 
- Compose mount: `./config/99-soc-json-log.conf:/etc/nginx/conf.d/99-soc-json-log.conf:ro` 
- Duplicate prevention: `access_log off;` is set before `access_log /var/log/nginx/access.log soc_json;` 
 
Apply sequence: 
1. `docker-compose up -d` 
2. `docker exec waf nginx -t` 
3. `docker exec waf nginx -s reload`

## Board API method exception scope
- PUT/DELETE allowed only for /api/board/posts/[id] and /api/board/posts/[postId]/comments/[commentId].
- OPTIONS allowed only for /api/board/posts/* (preflight).
- Applied Rule IDs: 990130, 990131, 990132 (path+method scoped 911100 exception).
