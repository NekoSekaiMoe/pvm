#!/usr/bin/env python3
"""Query GitHub Actions CI status for this repo.

Auth: reads the github.com token from ~/.netrc (same credential git push
uses); falls back to GITHUB_TOKEN / GH_TOKEN env vars.

Usage:
  python3 scripts/ci_status.py                     # recent runs (current branch)
  python3 scripts/ci_status.py --branch main       # another branch
  python3 scripts/ci_status.py --all               # all branches, recent runs
  python3 scripts/ci_status.py --jobs              # + job/step breakdown of newest run
  python3 scripts/ci_status.py --jobs --sha acc6622  # breakdown of a specific run
  python3 scripts/ci_status.py --pages 5           # more history
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import socket
from netrc import netrc

API = "https://api.github.com"


def load_token():
    for var in ("GITHUB_TOKEN", "GH_TOKEN"):
        if os.environ.get(var):
            return os.environ[var]
    try:
        auth = netrc().authenticators("github.com")
        if auth:
            return auth[2]  # (login, account, password)
    except FileNotFoundError:
        pass
    sys.exit("no token: put one in ~/.netrc (machine github.com login x password TOKEN) "
             "or export GITHUB_TOKEN")


def api_get(token, path):
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(API + path, headers=headers)
    try:
        with urllib.request.urlopen(req) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        # A fine-grained token scoped elsewhere yields 404 even on public
        # repos; retry anonymous (public repos answer without auth).
        if e.code == 404 and token:
            return api_get(None, path)
        raise



def get_repo():
    origin = os.popen("git config --get remote.origin.url").read().strip()
    path = urllib.parse.urlparse(origin).path if "://" in origin else ":" + origin
    full = path.lstrip(":/")
    return full.removesuffix(".git")


def fetch_runs(token, repo, branch, pages):
    runs = []
    for page in range(1, pages + 1):
        path = f"/repos/{repo}/actions/runs?per_page=50&page={page}"
        if branch:
            path += f"&branch={branch}"
        batch = api_get(token, path).get("workflow_runs", [])
        runs.extend(batch)
        if len(batch) < 50:
            break
    return runs


def show_jobs(token, repo, run_id):
    jobs = api_get(token, f"/repos/{repo}/actions/runs/{run_id}/jobs").get("jobs", [])
    for j in jobs:
        print(f"  {j['name']:<45} {j['conclusion'] or j['status']}")
        for s in j.get("steps", []):
            mark = "" if s["conclusion"] != "skipped" else " (skipped)"
            print(f"      - {s['name']}: {s['conclusion'] or s['status']}{mark}")


def force_ipv4():
    """Pin every socket to AF_INET. api.github.com also publishes AAAA
    records that blackhole on this network; urllib tries them all and
    reports the first (timeout) failure. curl survives via happy-eyeballs,
    which urllib lacks."""
    orig = socket.getaddrinfo

    def v4only(host, port, family=0, type=0, proto=0, flags=0):
        return orig(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = v4only


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--branch", default=None, help="default: current branch")
    ap.add_argument("--all", action="store_true", help="ignore branch filter")
    ap.add_argument("--pages", type=int, default=1)
    ap.add_argument("--sha", help="short sha prefix to filter/show jobs for")
    ap.add_argument("--jobs", action="store_true", help="show job/step breakdown")
    args = ap.parse_args()

    force_ipv4()

    token = load_token()
    repo = get_repo()
    branch = None if args.all else (args.branch or os.popen(
        "git branch --show-current").read().strip())

    runs = fetch_runs(token, repo, branch, args.pages)
    if not runs:
        print(f"no runs found (repo={repo}, branch={branch})")
        return

    print(f"repo: {repo}   branch: {branch or '(all)'}\n")
    shown = 0
    for r in runs:
        sha = r["head_sha"][:7]
        if args.sha and not sha.startswith(args.sha):
            continue
        concl = r["conclusion"] or f"in-{r['status']}"
        print(f"{sha}  {r['run_number']:>5}  {concl:<10}  {r['event']:<10}  {r['created_at']}")
        shown += 1
        if args.jobs and (args.sha or shown == 1):
            run_id = r["id"]
            print(f"  run {run_id}: {r['name']}  ({r['html_url']})")
            show_jobs(token, repo, run_id)
    if args.sha and shown == 0:
        print(f"no runs for sha {args.sha!r}")


if __name__ == "__main__":
    main()
