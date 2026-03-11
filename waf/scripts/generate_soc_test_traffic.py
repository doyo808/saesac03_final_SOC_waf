#!/usr/bin/env python3
import argparse
import json
import random
import signal
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TECHNIQUES = [
    {"name": "sqli", "query": {"q": "union select 1,2"}, "body": {"input": "union select user,password from users"}},
    {"name": "xss", "query": {"q": "javascript:alert(1)"}, "body": {"input": "javascript:alert(1)"}},
    {"name": "cmdi", "query": {"cmd": ";id"}, "body": {"input": ";id"}},
    {"name": "traversal", "query": {"file": "../etc/passwd"}, "body": {"input": "../win.ini"}},
]

def random_private_ip():
    pick = random.randint(0, 2)
    if pick == 0:
        return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
    if pick == 1:
        return f"172.{random.randint(16,31)}.{random.randint(0,255)}.{random.randint(1,254)}"
    return f"192.168.{random.randint(0,255)}.{random.randint(1,254)}"

def build_url(base_url, extra_query):
    parts = urllib.parse.urlsplit(base_url)
    merged = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
    merged.update(extra_query)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, urllib.parse.urlencode(merged), parts.fragment))

def main():
    parser = argparse.ArgumentParser(description="Generate SOC WAF test logs continuously.")
    parser.add_argument("--url", default="http://127.0.0.1/soc-log-test")
    parser.add_argument("--secret", required=True)
    parser.add_argument("--method", choices=["GET", "POST"], default="POST")
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--jitter", type=float, default=0.2)
    parser.add_argument("--timeout", type=float, default=3.0)
    parser.add_argument("--count", type=int, default=0, help="0 means infinite")
    parser.add_argument("--fixed-ip", default="", help="fixed X-Forwarded-For")
    args = parser.parse_args()

    state = {"stop": False}
    def stop_handler(_sig, _frame):
        state["stop"] = True

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    sent = 0
    ok = 0
    fail = 0
    print(f"[start] target={args.url} method={args.method} interval={args.interval} count={args.count}")

    while not state["stop"]:
        if args.count and sent == args.count:
            break

        sent += 1
        attack = random.choice(TECHNIQUES)
        attack_name = attack["name"]
        fake_ip = args.fixed_ip if args.fixed_ip else random_private_ip()
        req_id = str(uuid.uuid4())

        query = {"event": "soc_test", "seq": str(sent), "tech": attack_name, "ts": str(int(time.time()))}
        query.update(attack["query"])
        url = build_url(args.url, query)

        body = {"event": "soc_test", "seq": sent, "technique": attack_name, "payload": attack["body"]["input"], "request_id": req_id}
        data = json.dumps(body).encode("utf-8") if args.method == "POST" else None

        headers = {"User-Agent": "soc-test-generator/1.0", "X-SOC-Test": args.secret, "X-Request-ID": req_id, "X-Forwarded-For": fake_ip, "Content-Type": "application/json"}
        req = urllib.request.Request(url, data=data, headers=headers, method=args.method)

        try:
            with urllib.request.urlopen(req, timeout=args.timeout) as resp:
                ok += 1
                print(f"[{sent}] ok status={resp.getcode()} tech={attack_name} xff={fake_ip}")
        except urllib.error.HTTPError as err:
            ok += 1
            print(f"[{sent}] http status={err.code} tech={attack_name} xff={fake_ip}")
        except Exception as err:
            fail += 1
            print(f"[{sent}] fail error={err} tech={attack_name} xff={fake_ip}")

        delta = args.interval * args.jitter
        wait = max(0.0, args.interval + random.uniform(-delta, delta))
        time.sleep(wait)

    print(f"[done] sent={sent} ok={ok} fail={fail}")

if __name__ == "__main__":
    main()
