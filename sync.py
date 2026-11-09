#!/usr/bin/env python3
"""Fetch a configured set of pages and store their table markup, gzipped, in an object store.

Standard library only. All endpoints, key lists and credentials come from the environment.
Output is counts and timings only.
"""
import concurrent.futures as cf
import datetime as dt
import gzip
import hashlib
import hmac
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36"
TABLE = re.compile(r"<table\b.*?</table>", re.I | re.S)
KEY_RE = re.compile(r"^[A-Za-z0-9_.-]{1,24}$")
CFG_OBJECT = "cfg/keys.json"


# ---------- planning ----------
def slot_of(now):
    m = now.hour * 60 + now.minute
    m -= m % 5
    return f"{m // 60:02d}{m % 60:02d}"


def plan(keys, prio, slot, mode, rotate=True):
    """Ordered list of (kind, key). Priority keys: both kinds every run. Other keys: with rotate, both kinds
    on alternating slots (each key every second slot, half of them per slot); without rotate, kind a every run
    and kind b on alternating slots. Close mode: everything."""
    idx = (int(slot[:2]) * 60 + int(slot[2:])) // 5
    pr = set(prio)
    first = [k for k in keys if k in pr]
    rest = [k for k in keys if k not in pr]
    if mode == "close":
        return [("a", k) for k in keys] + [("b", k) for k in keys]
    jobs = [("a", k) for k in first] + [("b", k) for k in first]
    if rotate:
        turn = [k for i, k in enumerate(rest) if (i + idx) % 2 == 0]
        return jobs + [("a", k) for k in turn] + [("b", k) for k in turn]
    return jobs + [("a", k) for k in rest] + [("b", k) for k in turn_half(rest, idx)]


def turn_half(rest, idx):
    return [k for i, k in enumerate(rest) if (i + idx) % 2 == 0]


# ---------- http ----------
def fetch(url, timeout=25):
    last = 0
    for _ in (0, 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.status, r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            last = e.code
            if e.code in (400, 401, 403, 404, 410):
                break
        except Exception:
            last = 0
        time.sleep(0.4 + random.random() * 0.4)
    return last, ""


def tables_of(html):
    return "".join(TABLE.findall(html))


def fetch_one(job, templates, jitter, deadline=None):
    kind, key = job
    if deadline is not None and time.time() > deadline:
        return {"p": kind, "k": key, "s": -1, "t": int(time.time()), "b": ""}
    time.sleep(random.random() * jitter)
    t = time.time()
    status, body = fetch(templates[kind].replace("{k}", urllib.parse.quote(key, safe="")))
    return {"p": kind, "k": key, "s": status, "t": int(t), "b": tables_of(body) if status == 200 else ""}


# ---------- object store (SigV4) ----------
def sign(method, path, query, headers, payload_hash, key_id, secret, amz_date, region="auto", service="s3"):
    date = amz_date[:8]
    names = sorted(headers)
    canon_headers = "".join(f"{n}:{headers[n].strip()}\n" for n in names)
    signed = ";".join(names)
    canonical = "\n".join([method, urllib.parse.quote(path, safe="/~"), query, canon_headers, signed, payload_hash])
    scope = f"{date}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical.encode()).hexdigest()])
    k = ("AWS4" + secret).encode()
    for part in (date, region, service, "aws4_request"):
        k = hmac.new(k, part.encode(), hashlib.sha256).digest()
    sig = hmac.new(k, to_sign.encode(), hashlib.sha256).hexdigest()
    return f"AWS4-HMAC-SHA256 Credential={key_id}/{scope}, SignedHeaders={signed}, Signature={sig}"


def store_request(cfg, method, key, body=b""):
    base = cfg["endpoint"].rstrip("/")
    host = urllib.parse.urlparse(base).netloc
    path = f"/{cfg['bucket']}/{key}"
    amz = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    ph = hashlib.sha256(body).hexdigest()
    headers = {"host": host, "x-amz-content-sha256": ph, "x-amz-date": amz}
    auth = sign(method, path, "", headers, ph, cfg["key_id"], cfg["secret"], amz)
    req = urllib.request.Request(base + urllib.parse.quote(path, safe="/~"), data=body if method == "PUT" else None,
                                 method=method,
                                 headers={"x-amz-content-sha256": ph, "x-amz-date": amz, "Authorization": auth})
    with urllib.request.urlopen(req, timeout=40) as r:
        return r.status, r.read()


def load_keys(cfg):
    """Keys from the store object (refreshed daily by the owner side), else from the environment."""
    data = None
    try:
        st, raw = store_request(cfg, "GET", CFG_OBJECT)
        if st == 200:
            data = json.loads(raw.decode("utf-8"))
    except Exception:
        data = None
    if not data:
        env = [k.strip() for k in os.environ.get("SRC_KEYS", "").split(",") if k.strip()]
        data = {"all": env, "prio": []}
    keys = [k for k in data.get("all", []) if KEY_RE.match(k)]
    prio = [k for k in data.get("prio", []) if KEY_RE.match(k)]
    return keys, prio


# ---------- run ----------
def main():
    t0 = time.time()
    need = ["SRC_URL_A", "SRC_URL_B", "S3_ENDPOINT", "S3_BUCKET", "S3_KEY_ID", "S3_SECRET"]
    if any(not os.environ.get(n) for n in need):
        print("missing configuration")
        return 2
    cfg = {"endpoint": os.environ["S3_ENDPOINT"], "bucket": os.environ["S3_BUCKET"],
           "key_id": os.environ["S3_KEY_ID"], "secret": os.environ["S3_SECRET"]}
    templates = {"a": os.environ["SRC_URL_A"], "b": os.environ["SRC_URL_B"]}
    mode = "close" if os.environ.get("MODE") == "close" else "tick"
    now = dt.datetime.now(dt.timezone.utc)
    slot = os.environ.get("SLOT", "")
    if not re.fullmatch(r"\d{4}", slot):
        slot = slot_of(now)
    day = os.environ.get("DAY", "")
    if not re.fullmatch(r"\d{8}", day):
        day = f"{now:%Y%m%d}"
    keys, prio = load_keys(cfg)
    if not keys:
        print("no keys")
        return 2
    jobs = plan(keys, prio, slot, mode, rotate=os.environ.get("SYNC_ROTATE", "1") != "0")
    workers = max(1, min(10, int(os.environ.get("SYNC_WORKERS", "8"))))
    budget = float(os.environ.get("SYNC_BUDGET", "100"))
    deadline = time.time() + budget if mode != "close" else None
    with cf.ThreadPoolExecutor(workers) as ex:
        recs = list(ex.map(lambda j: fetch_one(j, templates, 0.1, deadline), jobs))
    done = [r for r in recs if r["s"] != -1]
    skipped = len(recs) - len(done)
    recs = done
    ok = sum(1 for r in recs if r["s"] == 200)
    errs = {}
    for r in recs:
        if r["s"] != 200:
            errs[str(r["s"])] = errs.get(str(r["s"]), 0) + 1
    fetch_secs = round(time.time() - t0, 1)
    meta = {"v": 1, "slot": slot, "mode": mode, "t0": int(t0), "pages": len(recs), "ok": ok, "errs": errs, "skipped": skipped, "secs": fetch_secs}
    lines = [json.dumps(x, ensure_ascii=False, separators=(",", ":")) for x in [meta] + recs]
    raw = gzip.compress("\n".join(lines).encode("utf-8"), 6, mtime=0)
    name = "close" if mode == "close" else slot
    key = f"raw/{day}/{name}.jsonl.gz"
    stored = False
    for attempt in range(3):
        try:
            stored = store_request(cfg, "PUT", key, raw)[0] in (200, 201)
            if stored:
                break
        except Exception:
            time.sleep(1 + attempt)
    print(f"pages={len(recs)} ok={ok} skipped={skipped} errors={errs} bytes={len(raw)} fetch_s={fetch_secs} "
          f"total_s={round(time.time() - t0, 1)} stored={stored}")
    return 0 if stored and ok >= 0.7 * len(recs) else 1


if __name__ == "__main__":
    sys.exit(main())
