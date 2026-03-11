# WAF Runner Setup (No SSH)

This repository uses a self-hosted GitHub Actions runner to deploy WAF changes on push to the `waf` branch.

## Live path

- Live repository path on WAF server: `/waf/saesac03_final_SOC`
- Live compose path: `/waf/saesac03_final_SOC/waf`

The workflow resets the live repository to `origin/waf` and applies `docker-compose up -d`.

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
3. `docker-compose up -d` (or `docker compose up -d`)
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
