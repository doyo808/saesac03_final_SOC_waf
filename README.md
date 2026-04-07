# saesac03_final_SOC WAF

SOC 최종 프로젝트용 WAF 운영 저장소입니다. `owasp/modsecurity-crs:nginx` 이미지를 기준으로 ModSecurity CRS를 운영하며, `waf` 브랜치 배포는 self-hosted GitHub Actions runner가 담당합니다.

## 저장소 핵심 구성

- `.github/workflows/nginx-reload.yml`: 실서버 저장소 동기화, compose 재적용, `nginx -t`, reload 자동화
- `waf/docker-compose.yml`: WAF 컨테이너 정의와 런타임 환경 변수 적용 지점
- `waf/config/99-soc-json-log.conf`: JSON 액세스 로그 포맷과 오타 기반 로그 억제 설정
- `waf/config/modsecurity.conf`: 현재 운영값을 설명하기 위한 기준 ModSecurity 설정
- `waf/rules/00_custom_rules.conf`: 프로젝트 전용 false positive 완화 규칙
- `waf/rules/00_custom_rules.disabled.conf`: 커스텀 룰을 임시로 비활성화할 때 사용하는 stub
- `waf/modes/*.env`: block, detect, off, current 모드 프리셋
- `waf/scripts/generate_soc_test_traffic.py`: SOC 로그 확인용 테스트 트래픽 생성 스크립트
- `docs/`: 운영 문서, Snort 대응표, 설계 참고 자료

## 디렉터리 구조

```text
.
|-- .github/
|   `-- workflows/
|       `-- nginx-reload.yml
|-- docs/
|   |-- reference/
|   |   `-- gemma-typo-rule-prompt.txt
|   |-- snort2-waf-rule-mapping.md
|   `-- waf-runner-setup.md
`-- waf/
    |-- config/
    |   |-- 99-soc-json-log.conf
    |   `-- modsecurity.conf
    |-- modes/
    |   |-- block.env
    |   |-- current.env
    |   |-- detect.env
    |   `-- off.env
    |-- rules/
    |   |-- 00_custom_rules.conf
    |   `-- 00_custom_rules.disabled.conf
    `-- scripts/
        `-- generate_soc_test_traffic.py
```

## 운영 흐름

1. 로컬에서는 `waf/modes/*.env` 중 필요한 모드를 골라 `docker compose --env-file ... up -d`로 스택을 올립니다.
2. 배포 시에는 `.github/workflows/nginx-reload.yml`가 실서버 경로 `/waf/saesac03_final_SOC`를 `origin/waf`와 동일한 상태로 맞춥니다.
3. 워크플로는 `waf/modes/current.env`를 기준으로 `docker compose` 또는 `docker-compose`를 실행합니다.
4. 적용 후 `docker exec waf nginx -t`와 `docker exec waf nginx -s reload`를 수행하고, 필요하면 `kill -HUP 1`로 한 번 더 재적용합니다.

## 모드 파일 정리

- `block.env`: 차단 모드. `MODSEC_RULE_ENGINE=On`
- `detect.env`: 관찰 모드. `MODSEC_RULE_ENGINE=DetectionOnly`
- `off.env`: 프록시 전용 모드. `MODSEC_RULE_ENGINE=Off`
- `current.env`: GitHub Actions 배포가 실제로 읽는 운영 기준 파일

모든 모드는 `PARANOIA=2`를 유지하고, `CUSTOM_RULES_FILE=./rules/00_custom_rules.conf`를 기본값으로 사용합니다. 커스텀 룰만 끄고 CRS는 유지하려면 `current.env`의 `CUSTOM_RULES_FILE`을 `./rules/00_custom_rules.disabled.conf`로 바꾸면 됩니다.

## 커스텀 룰 범위

`waf/rules/00_custom_rules.conf`는 CRS를 대체하는 공격 차단 룰셋이 아니라, 프로젝트 서비스 특성에 맞춘 오탐 완화와 허용 예외를 먼저 적용하는 파일입니다.

- `1001000-1001002`: 게시판 API 메서드 예외
- `1002000-1002002`: 검색 경로 쿼리 파라미터 튜닝
- `1003000-1003002`: 공개 문의 JSON 필드 튜닝
- `1004000-1004004`: 게시판, LMS, 인증 관련 본문 필드 튜닝
- `1005000-1005003`: 알려진 오타 경로 및 Referer 예외

## 문서 안내

- 운영/배포 절차: [docs/waf-runner-setup.md](docs/waf-runner-setup.md)
- Snort 초안 대응표: [docs/snort2-waf-rule-mapping.md](docs/snort2-waf-rule-mapping.md)
- 오타 패턴 설계 참고 프롬프트: [docs/reference/gemma-typo-rule-prompt.txt](docs/reference/gemma-typo-rule-prompt.txt)
