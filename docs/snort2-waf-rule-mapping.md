# Snort 2 초안과 현재 WAF 정책 대응표

## 범위

- 기준 시점: 현재 `waf` 브랜치 최신 상태
- WAF 런타임: `owasp/modsecurity-crs:nginx`
- 포함 범위:
  - 공식 OWASP CRS 기본 룰셋
  - `waf/rules/00_custom_rules.conf`
- 제외 범위:
  - `waf/rules/00_custom_rules.disabled.conf`
  - SOC 테스트용 synthetic 트래픽 스크립트
- 전제:
  - `waf/docker-compose.yml`에서 `PARANOIA=2`
  - `MODSEC_RULE_ENGINE=On`
  - `MODSEC_RULE_REMOVE_BY_ID=920350`

## 해석 기준

- 아래 Snort 초안은 로컬 WAF 룰 1개와 1:1 대응되는 경우보다, OWASP CRS의 룰군과 대응되는 경우가 더 많습니다.
- 저장소에 CRS 원본 파일을 vendoring 하지는 않으므로, 공격 탐지 계열은 공식 CRS 파일명 기준으로 설명합니다.
- `waf/rules/00_custom_rules.conf`는 공격 탐지 룰보다 false positive 완화와 허용 예외 중심이므로, 대부분은 Snort alert로 직접 옮기지 않습니다.

## Snort 2 초안

```snort
alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB SQLi UNION SELECT attempt";
    flow:to_server,established;
    content:"union"; nocase; fast_pattern;
    pcre:"/\bunion\b\s+(?:all\s+)?select\b/i";
    classtype:web-application-attack;
    sid:9001001; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB SQLi boolean tautology attempt";
    flow:to_server,established;
    content:"="; fast_pattern;
    pcre:"/(\bor\b|\band\b)\s+[\"'\x60]?\d+[\"'\x60]?\s*=\s*[\"'\x60]?\d+[\"'\x60]?/i";
    classtype:web-application-attack;
    sid:9001002; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB SQLi time-based function attempt";
    flow:to_server,established;
    content:"sleep"; nocase; fast_pattern;
    pcre:"/\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay)\s*\(/i";
    classtype:web-application-attack;
    sid:9001003; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB XSS script or javascript URI attempt";
    flow:to_server,established;
    content:"script"; nocase; fast_pattern;
    pcre:"/(?:<\s*script\b|javascript\s*:)/i";
    classtype:web-application-attack;
    sid:9001004; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB XSS event-handler injection attempt";
    flow:to_server,established;
    content:"onerror"; nocase; fast_pattern;
    pcre:"/\bon(?:error|load|click|mouseover|focus)\s*=/i";
    classtype:web-application-attack;
    sid:9001005; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB path traversal or LFI attempt";
    flow:to_server,established;
    content:"../"; fast_pattern;
    pcre:"/(?:\.\.\/|%2e%2e%2f|%2e%2e\/|\.\.%5c|%2e%2e%5c){1,}/i";
    classtype:web-application-attack;
    sid:9001006; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB remote file inclusion or wrapper attempt";
    flow:to_server,established;
    content:"http://"; nocase; fast_pattern;
    pcre:"/[?&][A-Za-z0-9_.-]{1,40}=(?:https?|ftp|file|php):\/\//i";
    classtype:web-application-attack;
    sid:9001007; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB command injection attempt";
    flow:to_server,established;
    content:";"; fast_pattern;
    pcre:"/[;&|`]\s*(?:id|whoami|uname|cat|curl|wget|bash|sh|nc|netcat|python|perl|php|powershell|cmd(?:\.exe)?)/i";
    classtype:web-application-attack;
    sid:9001008; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB scanner or automation user-agent";
    flow:to_server,established;
    content:"User-Agent|3a|"; nocase; fast_pattern;
    pcre:"/User-Agent\x3a\s*(?:sqlmap|nikto|nuclei|wpscan|dirbuster|gobuster|masscan|nessus|acunetix)/i";
    classtype:attempted-recon;
    sid:9001009; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB suspicious HTTP method";
    flow:to_server,established;
    pcre:"/^(?:TRACE|CONNECT|PROPFIND|MKCOL|MOVE|COPY)\s+/smi";
    classtype:misc-activity;
    sid:9001010; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB PUT or DELETE outside approved board API path";
    flow:to_server,established;
    pcre:"/^(?:PUT|DELETE)\s+(?!\/api\/board\/posts\/\d+(?:\/comments\/\d+)?\/?(?:\s|\?))/smi";
    classtype:misc-activity;
    sid:9001011; rev:1;
)

alert tcp $EXTERNAL_NET any -> $HOME_NET $HTTP_PORTS (
    msg:"LOCAL WEB repeated scanner activity from source";
    flow:to_server,established;
    content:"User-Agent|3a|"; nocase; fast_pattern;
    pcre:"/User-Agent\x3a\s*(?:sqlmap|nikto|nuclei|wpscan|dirbuster|gobuster|masscan|nessus|acunetix)/i";
    detection_filter:track by_src,count 5,seconds 60;
    classtype:attempted-recon;
    sid:9001012; rev:1;
)
```

## 대응표

| Snort SID | Snort 탐지 의도 | 대응 WAF 룰 | 대응 수준 | 비고 |
| --- | --- | --- | --- | --- |
| 9001001 | SQLi `UNION SELECT` | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | 로컬 파일이 아니라 기본 CRS SQLi 탐지군에 대응 |
| 9001002 | SQLi boolean tautology | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | `or 1=1`, `and 1=1` 류 |
| 9001003 | SQLi time-based 함수 | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | `sleep()`, `benchmark()`, `pg_sleep()` 류 |
| 9001004 | XSS script/javascript URI | 공식 CRS `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (`941xxx`) | 룰군 대응 | `<script`, `javascript:` 류 |
| 9001005 | XSS 이벤트 핸들러 | 공식 CRS `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (`941xxx`) | 룰군 대응 | `onerror=`, `onload=` 류 |
| 9001006 | Path Traversal / LFI | 공식 CRS `REQUEST-930-APPLICATION-ATTACK-LFI.conf` (`930xxx`) | 룰군 대응 | `../`, 인코딩 우회 포함 |
| 9001007 | RFI / wrapper | 공식 CRS `REQUEST-931-APPLICATION-ATTACK-RFI.conf` (`931xxx`) | 룰군 대응 | `http://`, `ftp://`, `file://`, `php://` 류 |
| 9001008 | Command Injection / RCE | 공식 CRS `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (`932xxx`) | 룰군 대응 | 일부 payload는 `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`와도 성격이 겹침 |
| 9001009 | 스캐너 User-Agent | 공식 CRS `REQUEST-913-SCANNER-DETECTION.conf` (`913xxx`) | 룰군 대응 | `sqlmap`, `nikto`, `nuclei` 류 |
| 9001010 | 의심스러운 HTTP 메서드 | 공식 CRS `REQUEST-911-METHOD-ENFORCEMENT.conf` 중심, 일부는 `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` 성격 | 부분 대응 | 프로젝트는 기본적으로 허용 메서드를 제한하고, 일부만 예외로 엽니다 |
| 9001011 | 게시판 외 경로의 `PUT`/`DELETE` 탐지 | 로컬 `1001000`, `1001001`, `1001002` + 공식 CRS `911100` | 정책 파생 | WAF는 board API만 예외 허용. Snort는 그 반대 범위를 탐지 |
| 9001012 | 동일 출발지 반복 스캐너 | 공식 CRS `REQUEST-913-SCANNER-DETECTION.conf` 기반 + Snort `detection_filter` | Snort 확장 | WAF의 단발 탐지를 Snort에서 소스 단위 상관으로 강화 |

## 로컬 WAF 정책 정리

### 1. 게시판 API 메서드 예외

파일: `waf/rules/00_custom_rules.conf`

- `1001000`: `PUT`, `DELETE`를 `/api/board/posts/[id]`에만 허용
- `1001001`: `PUT`, `DELETE`를 `/api/board/posts/[postId]/comments/[commentId]`에만 허용
- `1001002`: `OPTIONS`를 게시판 경로 preflight 용도로 허용

이 세 규칙은 CRS `911100`이 board API 정상 요청을 막지 않도록 허용 범위를 좁게 넓혀 주는 예외 규칙입니다. Snort 초안 `9001011`은 이 허용 범위를 제외한 나머지 `PUT`/`DELETE`를 수상한 행위로 보는 보완 탐지입니다.

### 2. 검색 및 본문 필드 오탐 완화

파일: `waf/rules/00_custom_rules.conf`

- `1002000-1002002`: 게시판/공지 검색 파라미터에 대한 SQLi, XSS, RCE, LFI 검사 범위 축소
- `1003000-1003002`: 공개 문의 JSON 필드(`subject`, `message`, `referenceUrl`) 완화
- `1004000-1004004`: 게시판, LMS, 인증 관련 JSON 필드 완화

이 규칙들은 공격 alert를 추가하는 목적이 아니라, 정상 서비스 입력을 더 정확하게 통과시키기 위한 false positive 튜닝입니다. 따라서 Snort alert 룰로 직접 대응시키기보다, 애플리케이션 특화 예외 정책으로 분류하는 편이 맞습니다.

### 3. 오타 경로 및 Referer 허용

파일: `waf/rules/00_custom_rules.conf`

- `1005000`: 공개 경로 오타 패턴 허용
- `1005001`: 앱 API 경로 오타 패턴 허용
- `1005002`: Referer 오타 패턴 허용
- `1005003`: LMS `course` 계열 오타 경로 허용

이 항목도 공격 탐지가 아니라 운영 중 반복적으로 발생하는 오타 접근의 잡음을 줄이기 위한 예외이므로, Snort alert로 직결하지 않습니다.

## Snort로 직접 옮기지 않는 로컬 룰

아래 룰들은 의도적으로 Snort 초안에서 제외했습니다.

- `1001000-1001002`
- `1002000-1002002`
- `1003000-1003002`
- `1004000-1004004`
- `1005000-1005003`

제외 이유는 다음과 같습니다.

- false positive 제어와 allowlist 성격이 강함
- 특정 서비스 입력 형식에 맞춘 예외 정책임
- IDS 관점의 공격 탐지 룰과 목적이 다름

즉 현재 Snort 초안은 "WAF의 공격 탐지 의도"를 대응시키고, "WAF의 예외 허용 로직과 오탐 완화 정책"은 별도 운영 정책으로 남겨 둔 상태입니다.

## 참고 파일

- 프로젝트 로컬 정책 파일: `waf/rules/00_custom_rules.conf`
- 운영 compose 설정: `waf/docker-compose.yml`
- 공식 CRS 룰 개요: https://coreruleset.org/docs/3-about-rules/rules/
- 공식 CRS Docker 이미지: https://github.com/coreruleset/modsecurity-crs-docker
