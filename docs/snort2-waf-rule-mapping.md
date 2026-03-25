# Snort 2 초안과 WAF 룰 대응표

## 범위

- 기준 시점: 현재 `waf` 브랜치 최신 상태
- WAF 런타임: `owasp/modsecurity-crs:nginx`
- 포함 범위:
  - 공식 OWASP CRS 기본 룰셋
  - `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`
- 제외 범위:
  - `waf/rules/custom_rules.conf`
  - SOC 테스트용 synthetic 룰
- 전제:
  - `waf/docker-compose.yml`에서 `PARANOIA=2`
  - `MODSEC_RULE_ENGINE=On`
  - `MODSEC_RULE_REMOVE_BY_ID=920350`

## 중요한 해석 기준

- 아래 Snort 룰 대부분은 로컬 파일에 있는 단일 WAF 룰 1개와 1:1 대응이 아니라, 공식 CRS의 "룰 파일 단위" 또는 "룰군 단위"에 대응합니다.
- 현재 저장소에는 CRS 원본 파일이 vendoring 되어 있지 않으므로, 기본 공격 탐지 계열은 공식 CRS 파일명 기준으로 매핑합니다.
- 반대로 `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`에 있는 룰들은 로컬 프로젝트 정책이므로, 이 문서에서 정확히 ID 단위로 매핑할 수 있습니다.

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
| 9001001 | SQLi `UNION SELECT` | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | 저장소 로컬 파일이 아니라 기본 CRS SQLi 탐지군에 대응 |
| 9001002 | SQLi boolean tautology | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | `or 1=1`, `and 1=1` 류 |
| 9001003 | SQLi time-based 함수 | 공식 CRS `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` (`942xxx`) | 룰군 대응 | `sleep()`, `benchmark()`, `pg_sleep()` 류 |
| 9001004 | XSS script/javascript URI | 공식 CRS `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (`941xxx`) | 룰군 대응 | `<script`, `javascript:` 류 |
| 9001005 | XSS 이벤트 핸들러 | 공식 CRS `REQUEST-941-APPLICATION-ATTACK-XSS.conf` (`941xxx`) | 룰군 대응 | `onerror=`, `onload=` 류 |
| 9001006 | Path Traversal / LFI | 공식 CRS `REQUEST-930-APPLICATION-ATTACK-LFI.conf` (`930xxx`) | 룰군 대응 | `../`, 인코딩 우회 포함 |
| 9001007 | RFI / wrapper | 공식 CRS `REQUEST-931-APPLICATION-ATTACK-RFI.conf` (`931xxx`) | 룰군 대응 | `http://`, `ftp://`, `file://`, `php://` 류 |
| 9001008 | Command Injection / RCE | 공식 CRS `REQUEST-932-APPLICATION-ATTACK-RCE.conf` (`932xxx`) | 룰군 대응 | 일부 payload는 `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`와도 성격이 겹침 |
| 9001009 | 스캐너 User-Agent | 공식 CRS `REQUEST-913-SCANNER-DETECTION.conf` (`913xxx`) | 룰군 대응 | `sqlmap`, `nikto`, `nuclei` 류 |
| 9001010 | 의심스러운 HTTP 메서드 | 공식 CRS `REQUEST-911-METHOD-ENFORCEMENT.conf` 중심, 일부는 `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` 성격 | 부분 대응 | 프로젝트는 기본적으로 허용 메서드를 제한하고, 일부만 예외로 엽니다 |
| 9001011 | 게시판 외 경로의 `PUT`/`DELETE` 탐지 | 로컬 `990130`, `990131`, `990132` + 공식 CRS `911100` | 정책 파생 | WAF는 board API만 예외 허용. Snort는 그 반대 범위를 탐지 |
| 9001012 | 동일 출발지 반복 스캐너 | 공식 CRS `REQUEST-913-SCANNER-DETECTION.conf` 기반 + Snort `detection_filter` | Snort 확장 | WAF의 단발 탐지를 Snort에서 소스 단위 상관으로 강화 |

## 로컬 WAF 정책과 직접 대응되는 항목

### 1. 게시판 API 메서드 예외

파일: `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`

- `990130`
  - `Host: kj.ac.kr`
  - `PUT`, `DELETE`
  - `/api/board/posts/[id]`
  - 의미: CRS `911100` 메서드 정책 전에 게시글 수정/삭제를 허용
- `990131`
  - `Host: kj.ac.kr`
  - `PUT`, `DELETE`
  - `/api/board/posts/[postId]/comments/[commentId]`
  - 의미: 댓글 수정/삭제 허용
- `990132`
  - `Host: kj.ac.kr`
  - `OPTIONS`
  - `/api/board/posts/*`
  - 의미: preflight 허용

여기에 대응하는 Snort 초안은 `9001011`입니다.

- WAF 관점:
  - board API에 대해서만 예외 허용
  - 나머지 경로는 기본 CRS 메서드 정책 유지
- Snort 관점:
  - 허용된 board API 범위를 제외한 `PUT`/`DELETE`를 탐지

즉 `9001011`은 특정 WAF 룰 1개를 복제한 것이 아니라, `990130`~`990132`가 만든 허용 범위를 거꾸로 뒤집어 네트워크 IDS 관점으로 표현한 정책 보완 룰입니다.

### 2. AI 기반 오타 suppress 룰

파일: `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`

- `1000001`: URI 오타 패턴이면 `920350` 제거
- `1000002`: Referer 오타 패턴이면 `920350` 제거
- `1000003`: Host가 IP 주소면 `920350` 제거

이 룰들은 Snort 초안에 대응되는 alert 룰이 없습니다.

이유:
- 이 룰들은 공격 탐지가 아니라 WAF 오탐 억제용입니다.
- 특히 현재 `waf/docker-compose.yml`에서 `MODSEC_RULE_REMOVE_BY_ID=920350`이 전역 적용되므로, 프로젝트 운영상 `920350`은 이미 suppress된 상태입니다.
- 따라서 Snort에 같은 성격의 alert를 만들면 실제 운영 의도와 충돌할 수 있습니다.

정리하면:
- `1000001`~`1000003`은 Snort로 "이관 대상"이 아니라 "이관 제외 대상"입니다.

## Snort 룰별 해설

### 9001001, 9001002, 9001003

- 대응 WAF 룰: `REQUEST-942-APPLICATION-ATTACK-SQLI.conf`
- 이유: 현재 프로젝트에서 SQLi를 별도 로컬 룰로 관리하지 않으므로 기본 CRS SQLi 룰군에 대응

### 9001004, 9001005

- 대응 WAF 룰: `REQUEST-941-APPLICATION-ATTACK-XSS.conf`
- 이유: XSS도 로컬 예외가 아니라 기본 CRS 탐지 영역

### 9001006

- 대응 WAF 룰: `REQUEST-930-APPLICATION-ATTACK-LFI.conf`
- 이유: path traversal, local file include 시도 대응

### 9001007

- 대응 WAF 룰: `REQUEST-931-APPLICATION-ATTACK-RFI.conf`
- 이유: 외부 URL 또는 wrapper를 인자로 주입하는 요청 대응

### 9001008

- 대응 WAF 룰: `REQUEST-932-APPLICATION-ATTACK-RCE.conf`
- 부분 중첩: `REQUEST-934-APPLICATION-ATTACK-GENERIC.conf`
- 이유: 명령 실행 시도와 일반 exploit 문법이 일부 겹치기 때문

### 9001009, 9001012

- 대응 WAF 룰: `REQUEST-913-SCANNER-DETECTION.conf`
- 차이점:
  - WAF는 개별 요청 단위 탐지
  - Snort `9001012`는 `detection_filter`를 추가해 같은 출발지의 반복 행위를 강조

### 9001010

- 대응 WAF 룰:
  - 기본적으로 `REQUEST-911-METHOD-ENFORCEMENT.conf`
  - 일부 메서드 이상행위는 `REQUEST-920-PROTOCOL-ENFORCEMENT.conf` 성격도 포함
- 이유: 비정상 메서드 사용은 메서드 정책 위반과 프로토콜 이상이 동시에 섞여 보일 수 있음

### 9001011

- 대응 WAF 룰:
  - 공식 CRS `911100` 메서드 정책
  - 로컬 예외 `990130`, `990131`, `990132`
- 의미:
  - WAF가 허용한 board API 예외를 제외한 나머지 `PUT`/`DELETE`는 여전히 수상
  - Snort에서 네트워크 레벨로 보조 탐지

## Snort로 옮기지 않은 WAF 룰

아래 룰들은 의도적으로 Snort 초안에서 제외했습니다.

- `1000001`
- `1000002`
- `1000003`
- `990130`
- `990131`
- `990132`

제외 이유:

- `1000001`~`1000003`
  - suppress / false positive 제어
  - alert 룰이 아님
- `990130`~`990132`
  - allowlist / 예외 허용
  - IDS alert 룰이 아님

즉 현재 Snort 초안은 "WAF의 공격 탐지 의도"만 옮기고, "WAF의 예외 허용 로직"은 직접 이관하지 않았습니다.

## 참고

- 프로젝트 로컬 정책 파일:
  - `waf/rules/REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`
  - `waf/docker-compose.yml`
- 공식 CRS 룰 개요:
  - https://coreruleset.org/docs/3-about-rules/rules/
- 공식 CRS Docker 이미지:
  - https://github.com/coreruleset/modsecurity-crs-docker
