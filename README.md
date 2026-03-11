# saesac03_final_SOC 
 
## Overview 
- WAF operations repository for the SOC final project. 
- Manages ModSecurity plus Nginx configuration on Docker. 
- Deploys by self-hosted GitHub Actions runner on the waf branch. 
 
## Repository Structure 
- waf/docker-compose.yml : WAF service definition. 
- waf/config/modsecurity.conf : global ModSecurity settings. 
- waf/rules/custom_rules.conf : custom WAF rules. 
- .github/workflows/nginx-reload.yml : deploy and reload workflow. 
- waf/scripts/generate_soc_test_traffic.py : SOC test log generator. 
- docs/waf-runner-setup.md : runner setup and deployment guide. 
 
## Deployment Flow 
1. Push changes to the waf branch. 
2. Workflow syncs /waf/saesac03_final_SOC on the WAF server. 
3. Workflow runs compose up, nginx config test, and nginx reload. 
 
## SOC Log Test 
- Test path: /soc-log-test 
- Test header: X-SOC-Test: CHANGE_ME_SECRET 
- Example command: 
  python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5
