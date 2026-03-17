# saesac03_final_SOC 
 
## Overview 
- WAF operations repository for the SOC final project. 
- Manages ModSecurity plus Nginx configuration on Docker. 
- Deploys by self-hosted GitHub Actions runner on the waf branch. 
 
## Repository Structure 
- waf/docker-compose.yml : WAF service definition. 
- waf/config/modsecurity.conf : reference ModSecurity settings kept for parity with compose env values. 
- waf/rules/custom_rules.conf : custom WAF rules. 
- .github/workflows/nginx-reload.yml : deploy and reload workflow. 
- waf/scripts/generate_soc_test_traffic.py : SOC test log generator. 
- docs/waf-runner-setup.md : runner setup and deployment guide. 
 
## Deployment Flow 
1. Push changes to the waf branch. 
2. Workflow syncs /waf/saesac03_final_SOC on the WAF server. 
3. Workflow runs compose up, nginx config test, and nginx reload. 

## Runtime Notes
- `owasp/modsecurity-crs:nginx` runtime settings are applied with `MODSEC_*` environment variables in `waf/docker-compose.yml`.
- Do not bind-mount `waf/config/modsecurity.conf` into the container; this previously caused restart-loop issues in this project.
 
## SOC Log Test 
- Test path: /soc-log-test 
- Test header: X-SOC-Test: CHANGE_ME_SECRET 
- Example command: 
  python3 soc_test_generator.py \
  --url http://127.0.0.1/soc-log-test \
  --secret CHANGE_ME_SECRET

