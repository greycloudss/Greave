import argparse, os, re, json, time, base64, threading, csv, html as ihtml, signal
from urllib import request, parse, error
from html.parser import HTMLParser
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, Empty

ID_REGEX = re.compile(r"\b(SRN)(\d{5})\b")
PWD_REGEX = re.compile(r"(?=\S*[A-Z])(?=\S*\d)(?=\S*[^A-Za-z0-9])\S{10}\b")
KEYWORD_REGEX = re.compile(r"\b(?:password|passwd|passcode|pwd)\b", re.IGNORECASE)

stop_ev = threading.Event()
write_q = Queue(maxsize=8192)
seen_keys = set()

class _HTMLText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.out = []
        self._in = {"script":False,"style":False,"a":False}
    def handle_starttag(self, tag, attrs):
        if tag in self._in: self._in[tag] = True
    def handle_endtag(self, tag):
        if tag in self._in: self._in[tag] = False
    def handle_data(self, data):
        if not any(self._in.values()) and data:
            self.out.append(data)
    def get_text(self):
        return " ".join(self.out)

def find(text, proximity):
    ids = [(m.group(1)+m.group(2), m.group(0), m.start()) for m in ID_REGEX.finditer(text)]
    pwds = [(m.group(0), m.start()) for m in PWD_REGEX.finditer(text)]
    kws  = [(m.group(0), m.start()) for m in KEYWORD_REGEX.finditer(text)]
    pairs = []
    if pwds and kws:
        ki = [i for _, i in kws]
        ki.sort()
        for pval, ppos in pwds:
            lo, hi = 0, len(ki) - 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if ki[mid] < ppos - proximity:
                    lo = mid + 1
                else:
                    hi = mid - 1
            j = lo
            while j < len(ki) and ki[j] <= ppos + proximity:
                pairs.append(("pwd_near_kw", pval, min(ppos, ki[j])))
                j += 1
    return ids, pairs

def snippet(text, idx, length):
    a = max(0, idx - length//2)
    b = min(len(text), idx + length//2)
    return text[a:b].replace("\n"," ").strip()

def writer(csv_path, ndjson_path):
    header = ["space","page_id","page_title","version","version_when","match_type","id_value","id_literal","password_value","context","url"]
    if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=header).writeheader()
    if not os.path.exists(ndjson_path):
        open(ndjson_path, "a", encoding="utf-8").close()
    fcsv = open(csv_path, "a", newline="", encoding="utf-8")
    fndj = open(ndjson_path, "a", encoding="utf-8")
    w = csv.DictWriter(fcsv, fieldnames=header)
    while True:
        try:
            r = write_q.get(timeout=0.2)
        except Empty:
            if stop_ev.is_set():
                break
            continue
        if r is None:
            break
        k = (r["space"], r["page_id"], r["version"], r["id_value"], r["password_value"], r["match_type"])
        if k in seen_keys:
            write_q.task_done()
            continue
        seen_keys.add(k)
        w.writerow(r)
        fcsv.flush()
        fndj.write(json.dumps(r, ensure_ascii=False) + "\n")
        fndj.flush()
        write_q.task_done()
    try:
        fcsv.flush(); fndj.flush()
    except Exception:
        pass
    try:
        fcsv.close(); fndj.close()
    except Exception:
        pass

def enqueue_rows(rows):
    if not rows:
        return
    for r in rows:
        while True:
            try:
                write_q.put(r, timeout=0.2)
                break
            except Exception:
                if stop_ev.is_set():
                    return

def preload_seen(ndjson_path):
    s = set()
    if os.path.exists(ndjson_path):
        try:
            with open(ndjson_path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        o = json.loads(line)
                        s.add((o.get("space"), o.get("page_id"), o.get("version"), o.get("id_value"), o.get("password_value"), o.get("match_type")))
                    except Exception:
                        continue
        except Exception:
            pass
    return s

def handle_signal(_s, _f):
    stop_ev.set()

def auth_header(email, token, mode, base):
    if mode == "auto":
        mode = "basic" if "atlassian.net" in base else "bearer"
    if mode == "bearer":
        return {"Authorization": f"Bearer {token}", "Accept": "application/json", "Connection": "close", "User-Agent": "Scraper/1.0"}
    b = base64.b64encode(f"{email}:{token}".encode()).decode()
    return {"Authorization": f"Basic {b}", "Accept": "application/json", "Connection": "close", "User-Agent": "Scraper/1.0"}

def http_get(base, path, params, headers, timeout, retries, backoff, max_backoff):
    url = f"{base}{path}"
    if params:
        url = f"{url}?{parse.urlencode(params)}"
    req = request.Request(url, headers=headers, method="GET")
    delay = max(0.05, backoff)
    tries = max(1, retries)
    for _ in range(tries):
        try:
            with request.urlopen(req, timeout=timeout) as resp:
                if resp.status != 200:
                    return {}
                return json.loads(resp.read().decode("utf-8"))
        except error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504):
                time.sleep(delay); delay = min(max_backoff, delay * 2); continue
            return {}
        except Exception:
            time.sleep(delay); delay = min(max_backoff, delay * 2); continue
    try:
        with request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                return {}
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return {}

def list_spaces(base, headers, timeout, retries, backoff, max_backoff, limit):
    start = 0
    while True:
        data = http_get(base, "/rest/api/space", {"limit": limit, "start": start}, headers, timeout, retries, backoff, max_backoff)
        results = data.get("results", [])
        for r in results:
            k = r.get("key")
            if k:
                yield k
        if not data.get("_links", {}).get("next"):
            break
        start += len(results)

def list_pages(base, space, headers, timeout, retries, backoff, max_backoff, limit, out_q):
    start = 0
    while True:
        params = {"type":"page","limit":limit,"start":start,"expand":"version","spaceKey":space}
        data = http_get(base, "/rest/api/content", params, headers, timeout, retries, backoff, max_backoff)
        results = data.get("results", [])
        for r in results:
            out_q.put((space, r))
        if not data.get("_links", {}).get("next"):
            break
        start += len(results)

def get_page(base, cid, headers, timeout, retries, backoff, max_backoff, status="current", version=None):
    params = {"expand":"body.storage,version,history"}
    if status == "historical" and version is not None:
        params["status"] = "historical"; params["version"] = str(version)
    return http_get(base, f"/rest/api/content/{cid}", params, headers, timeout, retries, backoff, max_backoff)

def list_versions(base, cid, headers, timeout, retries, backoff, max_backoff):
    start = 0
    while True:
        data = http_get(base, f"/rest/api/content/{cid}/version", {"limit":100,"start":start}, headers, timeout, retries, backoff, max_backoff)
        res = data.get("results", [])
        for v in res:
            yield v
        if not data.get("_links", {}).get("next"):
            break
        start += len(res)

def html_to_text_http(s):
    p = _HTMLText()
    try:
        p.feed(s or "")
    except Exception:
        pass
    return ihtml.unescape(p.get_text())

def scan_current(base, space_key, item, headers, timeout, retries, backoff, max_backoff, ctx_len):
    cid = item.get("id")
    webui = item.get("_links", {}).get("webui","")
    page = get_page(base, cid, headers, timeout, retries, backoff, max_backoff, "current", None)
    title = page.get("title","")
    v = page.get("version",{}) or {}
    vnum = v.get("number")
    vwhen = v.get("when")
    body_html = page.get("body",{}).get("storage",{}).get("value","") or ""
    body = html_to_text_http(body_html)
    ids, pairs = find(body, ctx_len)
    out = []
    if ids and pairs:
        for idm in ids:
            for kind, pval, pos in pairs:
                out.append({
                    "space":space_key,"page_id":cid,"page_title":title,"version":vnum,"version_when":vwhen,
                    "match_type":kind,"id_value":idm[0],"id_literal":idm[1],"password_value":pval,
                    "context":snippet(body, pos, ctx_len),"url":f"{base}{webui}"
                })
    return out, vnum, webui

def _scan_hist_version(base, space_key, cid, webui, vn, v_meta, headers, timeout, retries, backoff, max_backoff, ctx_len):
    hist = get_page(base, cid, headers, timeout, retries, backoff, max_backoff, "historical", vn)
    body_html = hist.get("body",{}).get("storage",{}).get("value","") or ""
    body = html_to_text_http(body_html)
    title = hist.get("title","")
    vwhen = v_meta.get("when") or hist.get("version",{}).get("when")
    ids, pairs = find(body, ctx_len)
    out = []
    if ids and pairs:
        url = f"{base}{v_meta.get('_links',{}).get('webui', webui)}"
        for idm in ids:
            for kind, pval, pos in pairs:
                out.append({
                    "space":space_key,"page_id":cid,"page_title":title,"version":vn,"version_when":vwhen,
                    "match_type":kind,"id_value":idm[0],"id_literal":idm[1],"password_value":pval,
                    "context":snippet(body, pos, ctx_len),"url":url
                })
    return out

def scan_history(base, space_key, cid, webui, current_v, headers, timeout, retries, backoff, max_backoff, ctx_len, max_versions, hist_workers):
    versions = []
    for v in list_versions(base, cid, headers, timeout, retries, backoff, max_backoff):
        vn = v.get("number")
        if isinstance(vn, int) and vn != current_v:
            versions.append((vn, v))
    if max_versions and len(versions) > max_versions:
        versions = versions[:max_versions]
    out = []
    if not versions:
        return out
    q = Queue()
    for vn, vmeta in versions:
        q.put((vn, vmeta))
    res_q = Queue()
    def hv_worker():
        while True:
            try:
                vn, vmeta = q.get_nowait()
            except Empty:
                break
            try:
                r = _scan_hist_version(base, space_key, cid, webui, vn, vmeta, headers, timeout, retries, backoff, max_backoff, ctx_len)
                if r:
                    for row in r: res_q.put(row)
            except Exception:
                pass
            finally:
                q.task_done()
    threads = []
    n = max(1, hist_workers)
    for _ in range(n):
        t = threading.Thread(target=hv_worker, daemon=True)
        t.start()
        threads.append(t)
    q.join()
    for t in threads: t.join()
    res = []
    while not res_q.empty():
        res.append(res_q.get())
    return res

def page_worker(page_q, base, headers, timeout, retries, backoff, max_backoff, ctx_len, include_history, max_versions, hist_workers):
    while True:
        try:
            space_key, item = page_q.get(timeout=1)
        except Empty:
            break
        try:
            rows, vnum, webui = scan_current(base, space_key, item, headers, timeout, retries, backoff, max_backoff, ctx_len)
            enqueue_rows(rows)
            if include_history and vnum:
                cid = item.get("id")
                hist_rows = scan_history(base, space_key, cid, webui, vnum, headers, timeout, retries, backoff, max_backoff, ctx_len, max_versions, hist_workers)
                enqueue_rows(hist_rows)
        except Exception:
            pass
        finally:
            page_q.task_done()

def likely_text(sample):
    if not sample:
        return False
    if b"\x00" in sample:
        return False
    ascii_print = sum(32 <= b <= 126 or b in (9,10,13) for b in sample)
    return ascii_print / len(sample) >= 0.7

def read_text(path, max_bytes):
    try:
        with open(path, "rb") as f:
            head = f.read(min(8192, max_bytes))
            if not likely_text(head):
                return ""
            rem = b""
            if len(head) < max_bytes:
                rem = f.read(max_bytes - len(head))
            data = head + rem
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            return data.decode("latin-1", errors="ignore")
    except Exception:
        return ""

def html_to_text_fs(s):
    return ihtml.unescape(s or "")

def split_name_ext(path):
    base, ext = os.path.splitext(os.path.basename(path))
    return base, ext.lower().lstrip(".")

def should_scan_file(path, include_exts, exclude_exts):
    _, ext = split_name_ext(path)
    if include_exts and ext not in include_exts:
        return False
    if exclude_exts and ext in exclude_exts:
        return False
    return True

def walk_files(root, follow_symlinks, include_exts, exclude_exts):
    stack = [root]
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                for entry in it:
                    if entry.is_dir(follow_symlinks=follow_symlinks):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=follow_symlinks):
                        if should_scan_file(entry.path, include_exts, exclude_exts):
                            yield entry.path
        except Exception:
            continue

def scan_file(root, path, ctx_len, max_bytes):
    if stop_ev.is_set():
        return []
    t = read_text(path, max_bytes)
    if not t:
        return []
    b = html_to_text_fs(t)
    ids, pairs = find(b, ctx_len)
    if not (ids and pairs):
        return []
    rel = os.path.relpath(path, root)
    try:
        mtime = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(os.path.getmtime(path)))
    except Exception:
        mtime = ""
    out = []
    for idm in ids:
        for kind, pval, pos in pairs:
            out.append({
                "space": os.path.splitdrive(root)[0] or root,
                "page_id": rel.replace("\\", "/"),
                "page_title": os.path.basename(path),
                "version": "",
                "version_when": mtime,
                "match_type": kind,
                "id_value": idm[0],
                "id_literal": idm[1],
                "password_value": pval,
                "context": snippet(b, pos, ctx_len),
                "url": "file:///" + path.replace("\\", "/")
            })
    return out

def scan_fs_main(args):
    include_exts = set([e.strip().lower() for e in args.include_ext.split(",") if e.strip()]) if args.include_ext else set()
    exclude_exts = set([e.strip().lower() for e in args.exclude_ext.split(",") if e.strip()]) if args.exclude_ext else set()
    files = list(walk_files(args.root, args.follow_symlinks, include_exts, exclude_exts))
    wt = threading.Thread(target=writer, args=(args.csv, args.ndjson), daemon=True)
    wt.start()
    try:
        with ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
            futs = [ex.submit(scan_file, args.root, p, args.context_len, args.max_bytes) for p in files]
            for f in as_completed(futs):
                if stop_ev.is_set():
                    break
                try:
                    rows = f.result()
                except Exception:
                    rows = []
                enqueue_rows(rows)
    finally:
        stop_ev.set()
        try:
            write_q.put(None, timeout=0.2)
        except Exception:
            pass
        wt.join()

def scan_http_main(args):
    base = args.base_url.rstrip("/")
    if "atlassian.net" in base and not base.endswith("/wiki"):
        base = base + "/wiki"
    headers = auth_header(args.email, args.api_token, args.auth, base)
    spaces = [args.space] if args.space else list(list_spaces(base, headers, args.timeout, args.retries, args.backoff, args.max_backoff, args.list_limit))
    page_q = Queue(maxsize=max(64, args.workers * 4))
    prod_threads = []
    for sk in spaces:
        t = threading.Thread(target=list_pages, args=(base, sk, headers, args.timeout, args.retries, args.backoff, args.max_backoff, args.list_limit, page_q), daemon=True)
        t.start()
        prod_threads.append(t)
    hist_workers = max(1, min(8, args.workers // 2)) if args.include_history else 1
    workers = []
    for _ in range(max(1, args.workers)):
        t = threading.Thread(target=page_worker, args=(page_q, base, headers, args.timeout, args.retries, args.backoff, args.max_backoff, args.context_len, args.include_history, args.max_versions, hist_workers), daemon=True)
        t.start()
        workers.append(t)
    wt = threading.Thread(target=writer, args=(args.csv, args.ndjson), daemon=True)
    wt.start()
    for t in prod_threads: t.join()
    page_q.join()
    for t in workers: t.join()
    stop_ev.set()
    try:
        write_q.put(None, timeout=0.2)
    except Exception:
        pass
    wt.join()

def main():
    for sig in ("SIGINT","SIGTERM","SIGBREAK"):
        if hasattr(signal, sig):
            try:
                signal.signal(getattr(signal, sig), handle_signal)
            except Exception:
                pass
    p = argparse.ArgumentParser()
    p.add_argument("--mode", choices=["fs","http"], required=True)
    p.add_argument("--root")
    p.add_argument("--follow-symlinks", action="store_true")
    p.add_argument("--include-ext", default="txt,md,ini,conf,log,xml,json,html,htm,properties,cfg,config,sql,ps1,bat,cmd,sh,py,js,ts,cs,java,yaml,yml,rb,go,php,csv")
    p.add_argument("--exclude-ext", default="")
    p.add_argument("--max-bytes", type=int, default=8*1024*1024)
    p.add_argument("--base-url")
    p.add_argument("--email")
    p.add_argument("--api-token")
    p.add_argument("--space")
    p.add_argument("--list-limit", type=int, default=200)
    p.add_argument("--include-history", action="store_true")
    p.add_argument("--max-versions", type=int, default=0)
    p.add_argument("--timeout", type=float, default=20)
    p.add_argument("--retries", type=int, default=5)
    p.add_argument("--backoff", type=float, default=0.1)
    p.add_argument("--max-backoff", type=float, default=2.0)
    p.add_argument("--auth", choices=["auto","basic","bearer"], default="auto")
    p.add_argument("--workers", type=int, default=24)
    p.add_argument("--context-len", type=int, default=160)
    p.add_argument("--csv", default="results.csv")
    p.add_argument("--ndjson", default="results.ndjson")
    args = p.parse_args()
    global seen_keys
    seen_keys = preload_seen(args.ndjson)
    if args.mode == "fs":
        if not args.root:
            raise SystemExit("--root is required for --mode fs")
        scan_fs_main(args)
    else:
        req = [args.base_url, args.email, args.api_token]
        if not all(req):
            raise SystemExit("--base-url, --email and --api-token are required for --mode http")
        scan_http_main(args)

if __name__ == "__main__":
    main()
