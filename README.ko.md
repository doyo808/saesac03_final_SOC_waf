# saesac03_final_SOC WAF

## 개요

- SOC 최종 프로젝트용 WAF 운영 저장소입니다.
- Docker 기반 `owasp/modsecurity-crs:nginx` 이미지를 사용합니다.
- `waf` 브랜치 기준으로 self-hosted GitHub Actions runner를 통해 배포합니다.

## 저장소 구성

- `waf/docker-compose.yml`: WAF 서비스 정의와 런타임 환경 변수
- `waf/config/modsecurity.conf`: compose 환경값과 기준을 맞추기 위한 참고용 ModSecurity 설정
- `waf/config/99-soc-json-log.conf`: JSON 액세스 로그 설정
- `waf/modes/*.env`: block, detect, off 모드 프리셋
- `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`: CRS 전 실행이 필요한 런타임 예외와 전처리 규칙
- `waf/rules/custom_rules.conf`: 사용자 정의 WAF 탐지 규칙과 사이트별 로깅 규칙
- `.github/workflows/nginx-reload.yml`: 실서버 배포 및 reload 워크플로
- `waf/scripts/generate_soc_test_traffic.py`: SOC 테스트 트래픽 생성 스크립트
- `docs/waf-runner-setup.md`: runner 및 배포 설정 문서

## 빠른 시작

1. `waf/` 디렉터리로 이동합니다.
2. 필요한 모드 프리셋으로 스택을 실행합니다.
   - `docker compose --env-file ./modes/block.env up -d`
   - `docker compose --env-file ./modes/detect.env up -d`
   - `docker compose --env-file ./modes/off.env up -d`
3. 호스트에 standalone 바이너리만 있으면 `docker compose` 대신 `docker-compose`를 사용합니다.
4. Nginx 설정을 검증합니다.
   - `docker exec waf nginx -t`
5. Nginx를 다시 불러옵니다.
   - `docker exec waf nginx -s reload`

## 배포 흐름

1. `waf` 브랜치에 `waf/**` 또는 `.github/workflows/nginx-reload.yml` 변경을 push 하면 워크플로가 실행됩니다.
2. self-hosted `waf` 러너가 실서버 경로 `/waf/saesac03_final_SOC`를 `origin/waf`와 동일한 상태로 맞춥니다.
3. 워크플로는 Docker 권한을 직접 확인하고, 필요하면 `sudo` 경로로 `docker compose up -d` 또는 `docker-compose up -d`를 실행합니다.
4. `compose up`이 한 번 실패하면 `waf` 컨테이너를 한 번만 재생성한 뒤 `--force-recreate`로 재시도합니다.
5. 이후 `nginx -t`, `nginx -s reload`를 수행하고, reload 실패 시 `kill -HUP 1`로 fallback 합니다.
6. 마지막에 `docker ps`와 `docker logs --tail 30 waf`로 상태를 후확인합니다.

## 운영 메모

- ModSecurity 런타임 설정은 `waf/docker-compose.yml`의 `BACKEND`, `PARANOIA`, `MODSEC_*` 환경 변수로 적용합니다.
- `waf/config/modsecurity.conf`를 라이브 컨테이너에 직접 bind mount 하지 마세요. 이 이미지 계열은 환경 변수와 룰 파일 mount 방식에 맞춰져 있습니다.
- `waf/modes/block.env`, `detect.env`, `off.env`는 모두 `PARANOIA=2`를 유지하고 `MODSEC_RULE_ENGINE`만 다르게 적용합니다.
- `waf/docker-compose.yml`은 엔진 로드 시점에 `MODSEC_RULE_REMOVE_BY_ID=920350`을 적용합니다.
- CRS보다 먼저 실행되어야 하는 런타임 예외는 `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`에서 관리합니다.
- JSON 액세스 로그는 `waf/config/99-soc-json-log.conf`로 관리합니다.
- 오타 기반 잡음 로그 억제는 `99-soc-json-log.conf`의 URI/Referer 필터와 `custom_rules.conf`의 920350 kill switch 규칙이 함께 담당합니다.
- Board API 메서드 예외는 `990130`, `990131`, `990132` 규칙으로만 제한됩니다.

## SOC 테스트 트래픽

- DetectionOnly 예외는 `/soc-log-test` 경로와 `X-SOC-Test: CHANGE_ME_SECRET` 헤더에만 적용됩니다.
- 현재 기본 규칙은 `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`에서 소스 IP `127.0.0.1`도 함께 요구합니다.
- 로컬 루프백이 아닌 원격 테스트 호스트를 쓰려면 배포 전에 해당 IP를 규칙 파일에서 교체해야 합니다.
- 테스트 생성 스크립트는 `normal`, `error`, `waf` 그룹 시나리오를 순차 실행하고 결과를 JSONL 파일로 남깁니다.
- 예시 실행 명령:

`python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5`

- 선택 옵션:
  - `--repeat-per-scenario`: 시나리오별 반복 횟수를 조정합니다.
  - `--scenario-filter`: 그룹 또는 시나리오 이름만 골라 실행합니다.
  - `--host-header`: 가상호스트 검증이 필요한 경우 Host 헤더를 지정합니다.
  - `--fixed-ip`: `X-Forwarded-For` 값을 고정합니다.
  - `--xff-list`: 순환 사용할 `X-Forwarded-For` 후보 목록을 지정합니다.
  - `--random-xff`: `X-Forwarded-For` 값을 무작위로 바꿉니다.
  - `--insecure`: HTTPS 테스트 시 인증서 검증을 건너뜁니다.
  - `--result-file`: 결과 저장 파일명을 바꿉니다.

## 추가 문서

runner 설치와 실서버 배포 절차는 [docs/waf-runner-setup.md](docs/waf-runner-setup.md)에서 확인할 수 있습니다.
