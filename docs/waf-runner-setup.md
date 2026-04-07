# WAF Runner 설정 및 배포 가이드

이 저장소는 self-hosted GitHub Actions runner를 사용해 `waf` 브랜치 변경사항을 실서버 WAF에 반영합니다. SSH 접속 대신 GitHub Actions와 로컬 Docker 권한만으로 배포가 끝나도록 구성되어 있습니다.

## 1. 운영 경로

- 실서버 저장소 경로: `/waf/saesac03_final_SOC`
- 실서버 compose 작업 경로: `/waf/saesac03_final_SOC/waf`
- 배포 워크플로 파일: `.github/workflows/nginx-reload.yml`

실서버 워크플로는 운영 저장소를 `origin/waf`와 동일한 상태로 맞춘 뒤, `waf/modes/current.env`를 기준으로 compose를 다시 적용합니다.

## 2. 배포 흐름

`waf` 브랜치에 push가 들어오고 변경 범위가 `waf/**` 또는 `.github/workflows/nginx-reload.yml`에 포함되면 워크플로가 다음 순서로 실행됩니다.

1. 실서버 저장소에서 `git fetch origin waf`
2. `/waf/saesac03_final_SOC`에서 `git reset --hard origin/waf`
3. `/waf/saesac03_final_SOC/waf`로 이동
4. `docker compose --env-file ./modes/current.env up -d` 실행
5. compose 플러그인이 없으면 `docker-compose --env-file ./modes/current.env up -d`로 fallback
6. 최초 `compose up` 실패 시 `waf` 컨테이너를 한 번만 재생성한 뒤 `--force-recreate`로 재시도
7. `docker exec waf nginx -t`
8. `docker exec waf nginx -s reload`
9. reload 실패 시 `kill -HUP 1`로 한 번 더 적용
10. 마지막에 `docker ps`, `docker logs --tail 30 waf`로 상태 확인

## 3. Runner 요구사항

1. Runner는 Docker가 설치된 동일 서버에서 동작해야 합니다.
2. Runner 라벨에 `waf`가 포함되어야 합니다.
3. Runner 계정은 Docker 명령을 직접 실행하거나 `sudo`로 실행할 수 있어야 합니다.

## 4. Docker 권한 구성

선택지는 둘 중 하나면 충분합니다.

- 방법 A: runner 사용자를 `docker` 그룹에 추가
- 방법 B: `sudo docker ...` 실행이 가능하도록 sudoers에 `NOPASSWD` 허용

워크플로는 먼저 일반 Docker 권한을 시도하고, 실패하면 `sudo docker` 경로를 자동으로 검사합니다.

## 5. 런타임 설정 기준

이 프로젝트는 `owasp/modsecurity-crs:nginx` 이미지를 사용하며, 런타임 설정은 `waf/docker-compose.yml`과 `waf/modes/*.env`에서 관리합니다.

- 기본 민감도: `PARANOIA=2`
- 기본 차단 모드: `MODSEC_RULE_ENGINE=On`
- 감사 로그: `MODSEC_AUDIT_ENGINE=RelevantOnly`
- 감사 로그 포맷: `MODSEC_AUDIT_LOG_FORMAT=JSON`
- 숫자형 Host 검사 예외: `MODSEC_RULE_REMOVE_BY_ID=920350`

`waf/config/modsecurity.conf`는 운영값을 설명하기 위한 기준 파일입니다. 이 파일을 실컨테이너 `/etc/modsecurity.d/modsecurity.conf`에 직접 bind mount 하지 않는 것을 권장합니다.

## 6. 모드 파일 운영 방식

`waf/modes/` 디렉터리에는 네 가지 파일이 있습니다.

- `block.env`: 차단 모드
- `detect.env`: DetectionOnly 모드
- `off.env`: ModSecurity 비활성화 모드
- `current.env`: 배포 워크플로가 실제로 읽는 활성 모드

모든 preset은 `PARANOIA=2`를 유지하고, 차이는 `MODSEC_RULE_ENGINE` 값에만 둡니다.

로컬에서 직접 실행할 때 예시는 다음과 같습니다.

```bash
docker compose --env-file ./modes/block.env up -d
docker compose --env-file ./modes/detect.env up -d
docker compose --env-file ./modes/off.env up -d
docker compose --env-file ./modes/current.env up -d
```

호스트에 compose 플러그인이 없으면 `docker-compose`로 바꿔 실행합니다.

## 7. 커스텀 룰 on/off

프로젝트 전용 false positive 완화 룰은 `waf/rules/00_custom_rules.conf`에 있습니다. compose는 `CUSTOM_RULES_FILE` 값을 통해 이 파일을 `/etc/modsecurity.d/owasp-crs/rules/00_custom_rules.conf`로 mount 합니다.

- 기본값: `CUSTOM_RULES_FILE=./rules/00_custom_rules.conf`
- 커스텀 룰 비활성화: `CUSTOM_RULES_FILE=./rules/00_custom_rules.disabled.conf`

즉, CRS는 유지한 채 프로젝트 룰만 끄고 싶다면 `waf/modes/current.env`의 `CUSTOM_RULES_FILE` 값을 disabled stub로 바꾸면 됩니다.

## 8. 룰 로드 순서

1. `CUSTOM_RULES_FILE`이 가리키는 `00_custom_rules.conf`
2. OWASP CRS 기본 rule set

이 구조의 목적은 프로젝트별 허용 예외와 오탐 완화를 먼저 반영하고, 실제 공격 차단은 CRS가 담당하게 하는 것입니다.

## 9. 주요 커스텀 룰 범위

- `1001000-1001002`: 게시판 API 메서드 예외
- `1002000-1002002`: 검색 파라미터 오탐 완화
- `1003000-1003002`: 공개 문의 JSON 필드 오탐 완화
- `1004000-1004004`: 게시판, LMS, 인증 관련 본문 필드 오탐 완화
- `1005000-1005003`: 알려진 오타 경로 및 Referer 허용

이 파일은 공격 탐지 강화용 로컬 차단 룰 모음이 아니라, 서비스 경로와 입력 특성에 맞춘 예외와 튜닝 파일입니다.

## 10. 적용 후 점검 순서

로컬 적용이든 배포 직후든 최소한 아래 순서는 유지하는 것이 안전합니다.

1. `docker compose --env-file ./modes/current.env up -d`
2. `docker exec waf nginx -t`
3. `docker exec waf nginx -s reload`

## 11. SOC 테스트 트래픽 생성

스크립트 경로는 `waf/scripts/generate_soc_test_traffic.py`입니다.

예시:

```bash
python3 waf/scripts/generate_soc_test_traffic.py --secret CHANGE_ME_SECRET --url http://127.0.0.1/soc-log-test --interval 0.5
```

주요 옵션:

- `--scenario-filter`: 특정 그룹 또는 시나리오만 실행
- `--fixed-ip`: 고정 `X-Forwarded-For` 사용
- `--xff-list`: 순환 IP 목록 지정
- `--random-xff`: 무작위 사설 IP 사용
- `--result-file`: 결과 JSONL 파일명 변경
- `--insecure`: HTTPS 테스트 시 인증서 검증 생략

## 12. JSON 액세스 로그

JSON 액세스 로그 설정은 `waf/config/99-soc-json-log.conf`에서 관리합니다.

- mount 경로: `./config/99-soc-json-log.conf:/etc/nginx/conf.d/99-soc-json-log.conf:ro`
- 중복 방지: `access_log off;` 후 필요한 출력만 다시 선언
- 목적: 표준 access log를 JSON 형식으로 남기고, 반복되는 오타 경로 잡음을 줄여 분석 품질을 높이는 것
