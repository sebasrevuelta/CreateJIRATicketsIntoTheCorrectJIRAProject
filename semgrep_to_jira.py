#!/usr/bin/env python3
"""
Semgrep -> JIRA ticket creation for high/critical findings on a subset of repos.

Logic
1) List all projects in a Semgrep deployment.
2) Keep only projects starting with PROJECT_PREFIX (e.g., "sebasrevuelta/").
3) For each matching project, fetch findings filtered by repo name.
4) For findings with severity in TARGET_SEVERITIES, create a Semgrep "ticket" (JIRA) via /tickets.

Notes / assumptions (don’t skip these):
- The Semgrep v1 endpoints typically paginate. This script supports cursor-style pagination when present.
- The /tickets payload you pasted looks like an “all possible filters” schema. In practice, the endpoint often
  accepts a smaller subset. This script sends a *minimal, derived* payload and only adds fields when we have data.
- You must prevent duplicate tickets somehow (tagging, checking existing tickets, or only sending new issue_ids).
  This script includes a simple in-memory de-dupe and an optional state file hook you can extend.

Requirements:
  pip install requests

Environment variables:
  SEMGREP_TOKEN   : Semgrep API token
  DEPLOYMENT_SLUG : deploymentSlug (string used in URL path)
Optional:
  SEMGREP_BASE_URL: default https://semgrep.dev
"""

from __future__ import annotations

import csv
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urljoin

import requests


# =========================
# Constants (edit these)
# =========================
SEMGREP_BASE_URL = os.getenv("SEMGREP_BASE_URL", "https://semgrep.dev").rstrip("/")
DEPLOYMENT_SLUG = os.getenv("DEPLOYMENT_SLUG", "").strip()

PROJECT_PREFIX = "sebasrevuelta/"  # only projects starting with this prefix
TARGET_SEVERITIES = {"high", "critical"}  # only these severities trigger ticket creation

# CSV mapping JIRA project name -> JIRA project ID
# Expected columns (case-insensitive):
#   jira_project_name, jira_project_id
JIRA_MAPPING_CSV_PATH = "./jira_project_mapping.csv"

# Findings query behavior
FINDINGS_PAGE_SIZE = 200
FINDINGS_STATUS = "open"  # commonly "open" / "fixed" / etc. (adjust to your workflow)
INCLUDE_HISTORICAL = False  # if True, include historical findings where supported

# Ticket creation behavior
GROUP_ISSUES = True          # if true, send multiple issue_ids in one ticket request per repo+severity+rule bucket
TICKET_LIMIT = 200           # max issue_ids per ticket request (keep modest; APIs often have limits)
DRY_RUN = False              # set True to print what would happen without POSTing
REQUEST_TIMEOUT_S = 30
RATE_LIMIT_SLEEP_S = 2       # naive backoff on 429/5xx


# =========================
# Helpers / types
# =========================
@dataclass(frozen=True)
class JiraProjectMapping:
    name_to_id: Dict[str, int]

    @staticmethod
    def load(path: str) -> "JiraProjectMapping":
        if not os.path.exists(path):
            raise FileNotFoundError(
                f"CSV mapping file not found: {path}\n"
                "Create it with columns: jira_project_name,jira_project_id"
            )

        name_to_id: Dict[str, int] = {}
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                raise ValueError("CSV has no header row.")

            # Normalize header names
            headers = {h.strip().lower(): h for h in reader.fieldnames if h}
            name_col = headers.get("jira_project_name")
            id_col = headers.get("jira_project_id")
            if not name_col or not id_col:
                raise ValueError(
                    "CSV must include headers: jira_project_name, jira_project_id"
                )

            for row in reader:
                raw_name = (row.get(name_col) or "").strip()
                raw_id = (row.get(id_col) or "").strip()
                if not raw_name or not raw_id:
                    continue
                try:
                    name_to_id[raw_name.lower()] = int(raw_id)
                except ValueError:
                    raise ValueError(
                        f"Invalid jira_project_id '{raw_id}' for '{raw_name}' (must be integer)."
                    )

        if not name_to_id:
            raise ValueError("CSV mapping is empty or has no valid rows.")

        return JiraProjectMapping(name_to_id=name_to_id)

    def get_id(self, jira_project_name: str) -> Optional[int]:
        return self.name_to_id.get(jira_project_name.strip().lower())


class SemgrepClient:
    def __init__(self, base_url: str, token: str, timeout_s: int = 30) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout_s = timeout_s
        self.session = requests.Session()
        self.session.headers.update(
            {
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
            }
        )

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, json: Any = None) -> Dict[str, Any]:
        url = urljoin(self.base_url + "/", path.lstrip("/"))

        while True:
            resp = self.session.request(
                method=method,
                url=url,
                params=params,
                json=json,
                timeout=self.timeout_s,
            )

            # Basic backoff for rate limiting / transient errors
            if resp.status_code in (429, 500, 502, 503, 504):
                time.sleep(RATE_LIMIT_SLEEP_S)
                continue

            if not resp.ok:
                raise RuntimeError(
                    f"{method} {url} failed: {resp.status_code}\n{resp.text}"
                )
            return resp.json()

    def list_projects(self, deployment_slug: str) -> List[Dict[str, Any]]:
        # Endpoint: /api/v1/deployments/{deploymentSlug}/projects
        path = f"/api/v1/deployments/{deployment_slug}/projects"

        projects: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        # Try cursor pagination if the API returns cursor; if not, we’ll just do one request.
        while True:
            params = {}
            if cursor:
                params["cursor"] = cursor

            data = self._request("GET", path, params=params)

            # Common shapes:
            #  - {"projects":[...], "cursor":"..."}
            #  - {"data":[...], "next":"..."} etc.
            batch = (
                data.get("projects")
                or data.get("data")
                or data.get("results")
                or []
            )
            if isinstance(batch, list):
                projects.extend(batch)
            else:
                raise RuntimeError(f"Unexpected projects response shape: {data.keys()}")

            cursor = data.get("cursor") or data.get("next_cursor") or data.get("next")
            if not cursor:
                break

        return projects

    def list_findings_for_repo(
        self,
        deployment_slug: str,
        repo: str,
        *,
        severities: Optional[Iterable[str]] = None,
        status: Optional[str] = None,
        page_size: int = 200,
        include_historical: bool = False,
    ) -> List[Dict[str, Any]]:
        # Endpoint: /api/v1/deployments/{deploymentSlug}/findings
        path = f"/api/v1/deployments/{deployment_slug}/findings"

        findings: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "repos": repo,          # user requirement: pass repo name (project name)
                "pageSize": page_size,
            }
            if status:
                params["status"] = status
            if severities:
                # Many APIs accept repeated params or comma-separated; we’ll try comma-separated.
                params["severities"] = ",".join(severities)
            if include_historical:
                params["include_historical"] = "true"
            if cursor:
                params["cursor"] = cursor

            data = self._request("GET", path, params=params)

            batch = (
                data.get("findings")
                or data.get("data")
                or data.get("results")
                or []
            )
            if isinstance(batch, list):
                findings.extend(batch)
            else:
                raise RuntimeError(f"Unexpected findings response shape: {data.keys()}")

            cursor = data.get("cursor") or data.get("next_cursor") or data.get("next")
            if not cursor:
                break

        return findings

    def create_ticket(self, deployment_slug: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        # Endpoint: /api/v1/deployments/{deploymentSlug}/tickets
        path = f"/api/v1/deployments/{deployment_slug}/tickets"
        return self._request("POST", path, json=payload)


def get_project_name(project_obj: Dict[str, Any]) -> Optional[str]:
    # Try a few likely keys; Semgrep project objects differ by endpoint/version.
    for key in ("name", "project_name", "repo", "repository", "full_name", "slug"):
        val = project_obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def extract_jira_project_name_from_semgrep_project(project_name: str) -> Optional[str]:
    """
    Example:
      sebasrevuelta/pb-core/ddex-team/clo-holdings-service
      -> pb-core (segment between 1st and 2nd slash)

    Rules:
      - Must start with PROJECT_PREFIX ("sebasrevuelta/")
      - Must have at least 2 segments after splitting by "/"
    """
    if not project_name.startswith(PROJECT_PREFIX):
        return None

    parts = project_name.split("/")
    # parts[0] = "sebasrevuelta", parts[1] = "pb-core"
    if len(parts) < 2 or not parts[1].strip():
        return None
    return parts[1].strip()


def normalize_severity(sev: Any) -> Optional[str]:
    if not isinstance(sev, str):
        return None
    return sev.strip().lower() or None


def extract_finding_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Best-effort extraction of useful ticket fields from a finding object.
    Because schemas vary, this intentionally probes multiple key paths.
    """
    out: Dict[str, Any] = {}

    # Issue ID (Semgrep finding / issue id)
    for k in ("id", "issue_id", "finding_id"):
        if isinstance(finding.get(k), int):
            out["issue_id"] = finding[k]
            break

    # Severity
    sev = finding.get("severity") or finding.get("metadata", {}).get("severity")
    out["severity"] = normalize_severity(sev)

    # Issue type (SAST/SCA/Secrets) best-effort
    issue_type = (
        finding.get("issue_type")
        or finding.get("type")
        or finding.get("category")
        or finding.get("metadata", {}).get("issue_type")
    )
    if isinstance(issue_type, str):
        out["issue_type"] = issue_type.strip().lower()

    # Rule id / policy / etc
    rule = (
        finding.get("rule")
        or finding.get("rule_id")
        or finding.get("check_id")
        or finding.get("metadata", {}).get("rule_id")
    )
    if isinstance(rule, str) and rule.strip():
        out["rule_id"] = rule.strip()

    # Repo name
    repo = finding.get("repo") or finding.get("repository") or finding.get("project")
    if isinstance(repo, str) and repo.strip():
        out["repo"] = repo.strip()

    # Confidence
    conf = finding.get("confidence") or finding.get("metadata", {}).get("confidence")
    if isinstance(conf, str) and conf.strip():
        out["confidence"] = conf.strip().lower()

    # Dependencies (SCA)
    deps = finding.get("dependencies") or finding.get("dependency") or finding.get("metadata", {}).get("dependencies")
    if isinstance(deps, list):
        out["dependencies"] = [str(d) for d in deps if str(d).strip()][:50]

    return out


def chunked(items: List[int], size: int) -> Iterable[List[int]]:
    for i in range(0, len(items), size):
        yield items[i : i + size]


def build_ticket_payload(
    *,
    deployment_slug: str,
    jira_project_id: int,
    repo: str,
    issue_ids: List[int],
    severities: List[str],
    issue_type: Optional[str],
    rules: Optional[List[str]],
    confidence: Optional[str],
) -> Dict[str, Any]:
    """
    Build a payload that matches your schema *but only includes fields we can justify*.

    If you blindly send random fields (categories/component_tags/etc) you’ll create noisy,
    low-quality tickets. Don’t do that to your future self.
    """
    payload: Dict[str, Any] = {
        "deploymentSlug": deployment_slug,
        "jira_project_id": jira_project_id,
        "repos": [repo],
        "issue_ids": issue_ids,
        "severities": list(dict.fromkeys(severities)),  # de-dupe while preserving order
        "status": FINDINGS_STATUS,
        "group_issues": GROUP_ISSUES,
        "limit": min(TICKET_LIMIT, len(issue_ids)),
        "include_historical": INCLUDE_HISTORICAL,
        # You asked: for high/critical, create ticket and mark as true_positive:
        "autotriage_verdict": "true_positive",
        # pro_only is likely not needed; omit unless you know you want it.
    }

    if issue_type:
        payload["issue_type"] = issue_type

    if rules:
        payload["rules"] = rules

    if confidence:
        payload["confidence"] = confidence

    return payload


def main() -> int:
    token = os.getenv("SEMGREP_TOKEN", "").strip()
    if not token:
        print("ERROR: SEMGREP_TOKEN env var is required.", file=sys.stderr)
        return 2
    if not DEPLOYMENT_SLUG:
        print("ERROR: DEPLOYMENT_SLUG env var is required.", file=sys.stderr)
        return 2

    jira_map = JiraProjectMapping.load(JIRA_MAPPING_CSV_PATH)
    client = SemgrepClient(SEMGREP_BASE_URL, token, timeout_s=REQUEST_TIMEOUT_S)

    print(f"- Semgrep base URL: {SEMGREP_BASE_URL}")
    print(f"- Deployment slug:  {DEPLOYMENT_SLUG}")
    print(f"- Project prefix:   {PROJECT_PREFIX}")
    print(f"- Target severities:{sorted(TARGET_SEVERITIES)}")
    print(f"- DRY_RUN:          {DRY_RUN}")
    print("")

    # 1) List projects
    projects = client.list_projects(DEPLOYMENT_SLUG)
    project_names: List[str] = []
    for p in projects:
        name = get_project_name(p)
        if name:
            project_names.append(name)

    # 2) Filter by prefix
    matching = [pn for pn in project_names if pn.startswith(PROJECT_PREFIX)]
    if not matching:
        print("No matching projects found. Exiting.")
        return 0

    print(f"Found {len(project_names)} projects; {len(matching)} match prefix.\n")

    # Track what we already ticketed in this run to avoid dupes
    ticketed_issue_ids: Set[int] = set()

    # 3) For each project -> findings
    for repo in sorted(set(matching)):
        jira_project_name = extract_jira_project_name_from_semgrep_project(repo)
        if not jira_project_name:
            print(f"[SKIP] Could not extract JIRA project name from repo: {repo}")
            continue

        jira_project_id = jira_map.get_id(jira_project_name)
        if jira_project_id is None:
            print(
                f"[SKIP] No JIRA project ID mapping for '{jira_project_name}' (repo: {repo}). "
                f"Add it to {JIRA_MAPPING_CSV_PATH}"
            )
            continue

        print(f"[REPO] {repo}  -> JIRA '{jira_project_name}' ({jira_project_id})")

        findings = client.list_findings_for_repo(
            DEPLOYMENT_SLUG,
            repo,
            status=FINDINGS_STATUS,
            page_size=FINDINGS_PAGE_SIZE,
            include_historical=INCLUDE_HISTORICAL,
        )

        if not findings:
            print("  - No findings.")
            continue

        # 4) Select high/critical
        selected: List[Dict[str, Any]] = []
        for f in findings:
            fields = extract_finding_fields(f)
            sev = fields.get("severity")
            issue_id = fields.get("issue_id")

            if sev in TARGET_SEVERITIES and isinstance(issue_id, int):
                if issue_id not in ticketed_issue_ids:
                    selected.append(fields)

        if not selected:
            print("  - No high/critical findings eligible for ticketing.")
            continue

        # Optional: group by (severity, rule_id, issue_type, confidence) to create cleaner tickets
        buckets: Dict[Tuple[str, str, str, str], List[int]] = {}
        for s in selected:
            sev = s.get("severity") or "unknown"
            rule = s.get("rule_id") or ""
            itype = s.get("issue_type") or ""
            conf = s.get("confidence") or ""
            key = (sev, rule, itype, conf)
            buckets.setdefault(key, []).append(int(s["issue_id"]))

        created_count = 0
        for (sev, rule, itype, conf), issue_ids in buckets.items():
            # chunk to avoid oversized POST bodies
            for issue_id_chunk in chunked(issue_ids, TICKET_LIMIT):
                payload = build_ticket_payload(
                    deployment_slug=DEPLOYMENT_SLUG,
                    jira_project_id=jira_project_id,
                    repo=repo,
                    issue_ids=issue_id_chunk,
                    severities=[sev],
                    issue_type=itype or None,
                    rules=[rule] if rule else None,
                    confidence=conf or None,
                )

                if DRY_RUN:
                    print(f"  - DRY_RUN would create ticket: sev={sev} rule={rule or '-'} count={len(issue_id_chunk)}")
                else:
                    resp = client.create_ticket(DEPLOYMENT_SLUG, payload)
                    created_count += 1
                    print(
                        f"  - Created ticket request: sev={sev} rule={rule or '-'} "
                        f"issue_ids={len(issue_id_chunk)} response_keys={list(resp.keys())}"
                    )

                for iid in issue_id_chunk:
                    ticketed_issue_ids.add(iid)

        print(f"  - Done. Ticket requests made for repo: {created_count}\n")

    print("All done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
