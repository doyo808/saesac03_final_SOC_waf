# WAF Runner Setup (No SSH)

This repository uses a self-hosted GitHub Actions runner to deploy WAF changes with separated test and production triggers.

## Live path

- Live repository path on WAF server: `/waf/saesac03_final_SOC`
- Live compose path: `/waf/saesac03_final_SOC/waf`

The workflows reset the live repository and apply `docker-compose up -d` on each deploy.

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

## Deployment flows

### Test flow (auto)

On `git push` to `codex/waf-test` branch with changes under `waf/**`, workflow `Nginx Reload Test` does:

1. `git fetch origin codex/waf-test`
2. `git reset --hard origin/codex/waf-test` in `/waf/saesac03_final_SOC`
3. `docker-compose up -d` (or `docker compose up -d`)
4. `docker exec waf nginx -t`
5. `docker exec waf nginx -s reload` (fallback: `kill -HUP 1`)

### Prod flow (manual)

Run workflow `Nginx Reload Prod` manually and set input `confirm` to `DEPLOY`.
Then workflow does:

1. `git fetch origin waf`
2. `git reset --hard origin/waf` in `/waf/saesac03_final_SOC`
3. `docker-compose up -d` (or `docker compose up -d`)
4. `docker exec waf nginx -t`
5. `docker exec waf nginx -s reload` (fallback: `kill -HUP 1`)
