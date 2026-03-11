#!/usr/bin/env python3
import argparse
import json
import random
import signal
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from datetime import datetime, timezone


SCENARIOS = [
    # 정상 로그
    {
        "group": "normal",
        "name": "normal_get",
        "method": "GET",
        "path_suffix": "",
        "query": {"case": "normal_get"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "normal",
        "name": "normal_post_json",
        "method": "POST",
        "path_suffix": "",
        "query": {"case": "normal_post_json"},
        "headers": {},
        "content_type": "application/json",
        "body_type": "json",
        "body": {"message": "hello", "type": "normal_json"},
    },
    {
        "group": "normal",
        "name": "normal_post_form",
        "method": "POST",
        "path_suffix": "",
        "query": {"case": "normal_post_form"},
        "headers": {},
        "content_type": "application/x-www-form-urlencoded",
        "body_type": "form",
        "body": {"message": "hello", "type": "normal_form"},
    },
    {
        "group": "normal",
        "name": "normal_head",
        "method": "HEAD",
        "path_suffix": "",
        "query": {"case": "normal_head"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "normal",
        "name": "normal_options",
        "method": "OPTIONS",
        "path_suffix": "",
        "query": {"case": "normal_options"},
        "headers": {
            "Origin": "https://waf.local",
            "Referer": "https://waf.local/test",
        },
        "content_type": None,
        "body_type": None,
        "body": None,
    },

    # 오류 / 비정상 응답 로그
    {
        "group": "error",
        "name": "not_found_404",
        "method": "GET",
        "path_suffix": "/not-found",
        "query": {"case": "not_found_404"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "error",
        "name": "method_not_allowed_405",
        "method": "POST",
        "path_suffix": "",
        "query": {"case": "method_not_allowed_405"},
        "headers": {},
        "content_type": "application/json",
        "body_type": "json",
        "body": {"message": "trigger_405"},
    },
    {
        "group": "error",
        "name": "malformed_json",
        "method": "POST",
        "path_suffix": "",
        "query": {"case": "malformed_json"},
        "headers": {},
        "content_type": "application/json",
        "body_type": "raw",
        "body": '{"broken_json": true',  # 닫는 괄호 없음
    },

    # WAF 탐지 로그
    {
        "group": "waf",
        "name": "waf_sqli",
        "method": "GET",
        "path_suffix": "",
        "query": {"q": "union select 1,2", "case": "waf_sqli"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "waf",
        "name": "waf_xss",
        "method": "GET",
        "path_suffix": "",
        "query": {"q": "javascript:alert(1)", "case": "waf_xss"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "waf",
        "name": "waf_cmdi",
        "method": "GET",
        "path_suffix": "",
        "query": {"cmd": ";id", "case": "waf_cmdi"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "waf",
        "name": "waf_traversal",
        "method": "GET",
        "path_suffix": "",
        "query": {"file": "../etc/passwd", "case": "waf_traversal"},
        "headers": {},
        "content_type": None,
        "body_type": None,
        "body": None,
    },
    {
        "group": "waf",
        "name": "waf_protocol_anomaly",
        "method": "GET",
        "path_suffix": "",
        "query": {"case": "waf_protocol_anomaly"},
        "headers": {
            "Transfer-Encoding": "chunked",
        },
        "content_type": None,
        "body_type": None,
        "body": None,
    },
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate sequential SOC WAF test logs for parsing validation."
    )
    parser.add_argument("--url", default="http://127.0.0.1/soc-log-test")
    parser.add_argument("--secret", required=True)
    parser.add_argument("--host-header", default="", help="Optional Host header, e.g. waf.local")
    parser.add_argument("--interval", type=float, default=1.0, help="Base delay between requests")
    parser.add_argument("--jitter", type=float, default=0.2, help="Delay jitter ratio")
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--repeat-per-scenario", type=int, default=5)
    parser.add_argument(
        "--scenario-filter",
        default="all",
        help="Comma-separated groups or scenario names. Example: normal,error,waf or normal_get,waf_sqli",
    )
    parser.add_argument("--fixed-ip", default="", help="Fixed X-Forwarded-For value")
    parser.add_argument(
        "--xff-list",
        default="192.168.119.117,192.168.119.118,192.168.119.119",
        help="Comma-separated X-Forwarded-For values to rotate when --fixed-ip is not used",
    )
    parser.add_argument("--random-xff", action="store_true", help="Use random private XFF instead of fixed/rotating values")
    parser.add_argument("--insecure", action="store_true", help="Ignore TLS certificate validation")
    parser.add_argument("--result-file", default="waf_log_generation_results.jsonl")
    return parser.parse_args()


def random_private_ip():
    pick = random.randint(0, 2)
    if pick == 0:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if pick == 1:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"


def build_url(base_url, path_suffix, extra_query):
    parts = urllib.parse.urlsplit(base_url)
    merged_query = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    merged_query.update(extra_query)

    base_path = parts.path.rstrip("/") if parts.path != "/" else ""
    suffix = path_suffix or ""
    final_path = f"{base_path}{suffix}" if suffix else base_path
    if not final_path:
        final_path = "/"

    return urllib.parse.urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            final_path,
            urllib.parse.urlencode(merged_query),
            parts.fragment,
        )
    )


def build_body_and_headers(scenario, iteration, sequence, request_id):
    body_type = scenario.get("body_type")
    body = scenario.get("body")
    headers = dict(scenario.get("headers", {}))

    payload = None
    if body_type == "json":
        merged_body = {
            "event": "soc_test",
            "sequence": sequence,
            "scenario_group": scenario["group"],
            "scenario_name": scenario["name"],
            "iteration": iteration,
            "request_id": request_id,
        }
        if isinstance(body, dict):
            merged_body.update(body)
        payload = json.dumps(merged_body).encode("utf-8")
    elif body_type == "form":
        merged_body = {
            "event": "soc_test",
            "sequence": str(sequence),
            "scenario_group": scenario["group"],
            "scenario_name": scenario["name"],
            "iteration": str(iteration),
            "request_id": request_id,
        }
        if isinstance(body, dict):
            for key, value in body.items():
                merged_body[key] = str(value)
        payload = urllib.parse.urlencode(merged_body).encode("utf-8")
    elif body_type == "raw":
        payload = str(body).encode("utf-8")

    if scenario.get("content_type"):
        headers["Content-Type"] = scenario["content_type"]

    return payload, headers


def select_scenarios(filter_text):
    if filter_text.lower() == "all":
        return SCENARIOS

    wanted = {item.strip() for item in filter_text.split(",") if item.strip()}
    selected = []
    for scenario in SCENARIOS:
        if scenario["group"] in wanted or scenario["name"] in wanted:
            selected.append(scenario)
    return selected


def classify_status(status_code):
    if 200 <= status_code <= 299:
        return "success_2xx"
    if 300 <= status_code <= 399:
        return "redirect_3xx"
    if 400 <= status_code <= 499:
        return "client_error_4xx"
    if 500 <= status_code <= 599:
        return "server_error_5xx"
    return "other"


def create_ssl_context(insecure):
    if not insecure:
        return None
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def make_headers(args, scenario, iteration, request_id, xff_value):
    headers = {
        "User-Agent": "soc-test-generator/2.0",
        "X-SOC-Test": args.secret,
        "X-Request-ID": request_id,
        "X-Scenario-Group": scenario["group"],
        "X-Scenario-Name": scenario["name"],
        "X-Scenario-Iteration": str(iteration),
        "X-Forwarded-For": xff_value,
    }
    if args.host_header:
        headers["Host"] = args.host_header
    headers.update(scenario.get("headers", {}))
    return headers


def choose_xff(args, sequence, xff_pool):
    if args.fixed_ip:
        return args.fixed_ip
    if args.random_xff:
        return random_private_ip()
    if not xff_pool:
        return "192.168.119.117"
    return xff_pool[(sequence - 1) % len(xff_pool)]


def write_result_line(fp, result):
    fp.write(json.dumps(result, ensure_ascii=False) + "\n")
    fp.flush()


def main():
    args = parse_args()
    selected_scenarios = select_scenarios(args.scenario_filter)

    if not selected_scenarios:
        raise SystemExit("선택된 시나리오가 없습니다. --scenario-filter 값을 확인하세요.")

    xff_pool = [item.strip() for item in args.xff_list.split(",") if item.strip()]
    ssl_context = create_ssl_context(args.insecure)

    state = {"stop": False}

    def stop_handler(_sig, _frame):
        state["stop"] = True

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    stats = {
        "total_sent": 0,
        "http_responses": 0,
        "success_2xx": 0,
        "redirect_3xx": 0,
        "client_error_4xx": 0,
        "server_error_5xx": 0,
        "network_failures": 0,
    }
    per_scenario_count = Counter()
    per_status_count = Counter()

    print(
        f"[start] url={args.url} repeat_per_scenario={args.repeat_per_scenario} "
        f"scenario_filter={args.scenario_filter} result_file={args.result_file}"
    )

    with open(args.result_file, "a", encoding="utf-8") as result_fp:
        sequence = 0

        for scenario in selected_scenarios:
            for iteration in range(1, args.repeat_per_scenario + 1):
                if state["stop"]:
                    break

                sequence += 1
                stats["total_sent"] += 1
                per_scenario_count[scenario["name"]] += 1

                request_id = str(uuid.uuid4())
                xff_value = choose_xff(args, sequence, xff_pool)

                query = {
                    "event": "soc_test",
                    "sequence": str(sequence),
                    "scenario_group": scenario["group"],
                    "scenario_name": scenario["name"],
                    "iteration": str(iteration),
                    "ts": str(int(time.time())),
                }
                query.update(scenario.get("query", {}))

                url = build_url(args.url, scenario.get("path_suffix", ""), query)
                body, extra_headers = build_body_and_headers(
                    scenario=scenario,
                    iteration=iteration,
                    sequence=sequence,
                    request_id=request_id,
                )
                headers = make_headers(
                    args=args,
                    scenario=scenario,
                    iteration=iteration,
                    request_id=request_id,
                    xff_value=xff_value,
                )
                headers.update(extra_headers)

                req = urllib.request.Request(
                    url=url,
                    data=body,
                    headers=headers,
                    method=scenario["method"],
                )

                started = time.perf_counter()
                status_code = None
                error_message = ""

                try:
                    with urllib.request.urlopen(req, timeout=args.timeout, context=ssl_context) as resp:
                        status_code = resp.getcode()
                except urllib.error.HTTPError as err:
                    status_code = err.code
                    error_message = f"HTTPError: {err.code}"
                except Exception as err:
                    error_message = str(err)

                elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
                timestamp = datetime.now(timezone.utc).isoformat()

                if status_code is not None:
                    stats["http_responses"] += 1
                    per_status_count[str(status_code)] += 1
                    bucket = classify_status(status_code)
                    if bucket in stats:
                        stats[bucket] += 1
                else:
                    stats["network_failures"] += 1

                result = {
                    "timestamp": timestamp,
                    "scenario_group": scenario["group"],
                    "scenario_name": scenario["name"],
                    "iteration": iteration,
                    "method": scenario["method"],
                    "url": url,
                    "status_code": status_code,
                    "request_id": request_id,
                    "x_forwarded_for": xff_value,
                    "elapsed_ms": elapsed_ms,
                    "error_message": error_message,
                }
                write_result_line(result_fp, result)

                print(
                    f"[{sequence:03d}] "
                    f"group={scenario['group']:<6} "
                    f"scenario={scenario['name']:<24} "
                    f"iter={iteration:<2} "
                    f"method={scenario['method']:<7} "
                    f"status={str(status_code):<4} "
                    f"xff={xff_value:<15} "
                    f"elapsed_ms={elapsed_ms:<8} "
                    f"request_id={request_id}"
                )

                if state["stop"]:
                    break

                delta = args.interval * args.jitter
                wait = max(0.0, args.interval + random.uniform(-delta, delta))
                time.sleep(wait)

            if state["stop"]:
                break

    print("\n[summary]")
    print(f"total_sent        : {stats['total_sent']}")
    print(f"http_responses    : {stats['http_responses']}")
    print(f"success_2xx       : {stats['success_2xx']}")
    print(f"redirect_3xx      : {stats['redirect_3xx']}")
    print(f"client_error_4xx  : {stats['client_error_4xx']}")
    print(f"server_error_5xx  : {stats['server_error_5xx']}")
    print(f"network_failures  : {stats['network_failures']}")

    print("\n[per_scenario_count]")
    for scenario_name, count in per_scenario_count.items():
        print(f"{scenario_name:<24} : {count}")

    print("\n[per_status_count]")
    for status, count in sorted(per_status_count.items(), key=lambda item: int(item[0])):
        print(f"{status:<4} : {count}")

    print(f"\n[result_file] {args.result_file}")


if __name__ == "__main__":
    main()
