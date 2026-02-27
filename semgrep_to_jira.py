#!/usr/bin/env python3

# Semgrep -> JIRA ticket creation for findings on a subset of repos.

# Logic
# 1) List all projects in a Semgrep deployment.
# 2) Keep only projects starting with PROJECT_PREFIX (e.g., "sebasrevuelta/").
# 3) For each matching project, fetch findings filtered by repo name and severity.
# 4) For each finding, create one Semgrep "ticket" (JIRA) via POST /tickets.

# Notes / assumptions (don't skip these):
# - The Semgrep v1 endpoints typically paginate. This script supports cursor-style pagination when present.
# - One POST request is made per finding.
# - You must prevent duplicate tickets somehow (tagging, checking existing tickets, or only sending new issue_ids).
#   This script includes a simple in-memory de-dupe you can extend.

# Requirements:
#   pip install requests

# Environment variables:
#   SEMGREP_TOKEN    : Semgrep API token (required)
#   DEPLOYMENT_SLUG  : deploymentSlug (string used in URL path, required)
#   JIRA_PROJECT_ID  : JIRA project ID (required; always included in payload)
# Optional:
#   SEMGREP_BASE_URL : default https://semgrep.dev


from __future__ import annotations

import argparse
import logging
import os
import time
from typing import Any, Dict, Iterable, List, Optional, Set
from urllib.parse import urljoin

import requests


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
logger = logging.getLogger(__name__)


# =========================
# Constants (edit these)
# =========================
SEMGREP_BASE_URL = os.getenv("SEMGREP_BASE_URL", "https://semgrep.dev").rstrip("/")
DEPLOYMENT_SLUG = os.getenv("DEPLOYMENT_SLUG", "").strip()

PROJECT_PREFIX = "sebasrevuelta/"  # only projects starting with this prefix

# JIRA project ID (required; always included in the ticket payload)
JIRA_PROJECT_ID = os.getenv("JIRA_PROJECT_ID", "").strip()

# Findings query behavior
FINDINGS_PAGE_SIZE = 200
FINDINGS_STATUS = "open"  # commonly "open" / "fixed" / etc. (adjust to your workflow)

# Misc
REQUEST_TIMEOUT_S = 30
RATE_LIMIT_SLEEP_S = 2   # naive backoff on 429/5xx


# =========================
# Helpers / types
# =========================
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
        path = f"/api/v1/deployments/{deployment_slug}/projects"

        projects: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {}
            if cursor:
                params["cursor"] = cursor

            data = self._request("GET", path, params=params)

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
        issue_type: Optional[str] = None,
        status: Optional[str] = None,
        page_size: int = 200,
    ) -> List[Dict[str, Any]]:
        path = f"/api/v1/deployments/{deployment_slug}/findings"

        findings: List[Dict[str, Any]] = []
        cursor: Optional[str] = None

        while True:
            params: Dict[str, Any] = {
                "repos": repo,
                "pageSize": page_size,
            }
            if status:
                params["status"] = status
            if severities:
                params["severities"] = ",".join(severities)
            if issue_type:
                params["issue_type"] = issue_type
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
        path = f"/api/v1/deployments/{deployment_slug}/tickets"
        return self._request("POST", path, json=payload)


def get_project_name(project_obj: Dict[str, Any]) -> Optional[str]:
    for key in ("name", "project_name", "repo", "repository", "full_name", "slug"):
        val = project_obj.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def extract_finding_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Best-effort extraction of ticket-relevant fields from a finding object.
    Because schemas vary, this intentionally probes multiple key paths.
    """
    out: Dict[str, Any] = {}

    # Issue ID (Semgrep finding / issue id)
    for k in ("id", "issue_id", "finding_id"):
        if isinstance(finding.get(k), int):
            out["issue_id"] = finding[k]
            break

    # Issue type (SAST/SCA/Secrets) best-effort
    issue_type = (
        finding.get("issue_type")
        or finding.get("type")
        or finding.get("category")
        or finding.get("metadata", {}).get("issue_type")
    )
    if isinstance(issue_type, str) and issue_type.strip():
        out["issue_type"] = issue_type.strip().lower()

    return out


def build_ticket_payload(
    *,
    issue_type: str,
    issue_id: int,
    jira_project_id: str,
) -> Dict[str, Any]:
    """
    Mandatory fields: issue_type, issue_ids, and jira_project_id.
    """
    return {
        "issue_type": issue_type,
        "issue_ids": [issue_id],
        "jira_project_id": jira_project_id,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Create JIRA tickets from Semgrep findings.")
    parser.add_argument(
        "--repo",
        metavar="REPO",
        default=None,
        help="Process a single repo (e.g. sebasrevuelta/AmazingRepo) instead of all prefix-matching projects.",
    )
    parser.add_argument(
        "--severities",
        metavar="SEV",
        nargs="+",
        default=["critical"],
        help="Severity levels to fetch and ticket (default: high critical).",
    )
    parser.add_argument(
        "--issue-type",
        choices=["sast", "sca"],
        default="sast",
        help="Issue type to filter findings and set on tickets (sast or sca, default: sast).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=True,
        help="Log actions without creating tickets (default: True). Pass --no-dry-run to create tickets.",
    )
    parser.add_argument(
        "--no-dry-run",
        dest="dry_run",
        action="store_false",
        help="Actually create tickets (disables dry run mode).",
    )
    args = parser.parse_args()

    target_severities: List[str] = [s.strip().lower() for s in args.severities if s.strip()]
    if not target_severities:
        logger.error("--severities must include at least one value.")
        return 2

    issue_type: str = args.issue_type
    dry_run: bool = args.dry_run

    token = os.getenv("SEMGREP_TOKEN", "").strip()
    if not token:
        logger.error("SEMGREP_TOKEN env var is required.")
        return 2
    if not DEPLOYMENT_SLUG:
        logger.error("DEPLOYMENT_SLUG env var is required.")
        return 2

    if not JIRA_PROJECT_ID:
        logger.error("JIRA_PROJECT_ID env var is required.")
        return 2

    jira_project_id: str = JIRA_PROJECT_ID

    client = SemgrepClient(SEMGREP_BASE_URL, token, timeout_s=REQUEST_TIMEOUT_S)

    logger.info("Semgrep base URL: %s", SEMGREP_BASE_URL)
    logger.info("Deployment slug:  %s", DEPLOYMENT_SLUG)
    logger.info("Project prefix:   %s", PROJECT_PREFIX)
    logger.info("Severities:       %s", target_severities)
    logger.info("Issue type:       %s", issue_type)
    logger.info("JIRA project ID:  %s", jira_project_id)
    logger.info("DRY_RUN:          %s", dry_run)

    # 1) Determine the list of repos to process
    if args.repo:
        matching = [args.repo.strip()]
        logger.info("Single-repo mode: %s", matching[0])
    else:
        projects = client.list_projects(DEPLOYMENT_SLUG)
        project_names: List[str] = []
        for p in projects:
            name = get_project_name(p)
            if name:
                project_names.append(name)

        matching = [pn for pn in project_names if pn.startswith(PROJECT_PREFIX)]
        if not matching:
            logger.info("No matching projects found. Exiting.")
            return 0

        logger.info("Found %d projects; %d match prefix.", len(project_names), len(matching))

    # Track already-ticketed issue IDs in this run to avoid duplicates
    ticketed_issue_ids: Set[int] = set()

    # 2) For each repo -> fetch findings (API-filtered by severity) -> one ticket per finding
    for repo in sorted(set(matching)):
        logger.info("[REPO] %s", repo)

        findings = client.list_findings_for_repo(
            DEPLOYMENT_SLUG,
            repo,
            severities=target_severities,
            issue_type=issue_type,
            status=FINDINGS_STATUS,
            page_size=FINDINGS_PAGE_SIZE,
        )

        if not findings:
            logger.info("  - No findings.")
            continue

        created_count = 0
        for f in findings:
            fields = extract_finding_fields(f)
            issue_id = fields.get("issue_id")

            if not isinstance(issue_id, int):
                continue
            if issue_id in ticketed_issue_ids:
                continue

            payload = build_ticket_payload(
                issue_type=issue_type,
                issue_id=issue_id,
                jira_project_id=jira_project_id,
            )

            if dry_run:
                logger.info("  - DRY_RUN would create ticket: issue_id=%d issue_type=%s", issue_id, issue_type)
            else:
                resp = client.create_ticket(DEPLOYMENT_SLUG, payload)
                created_count += 1
                logger.info("  - Created ticket: issue_id=%d issue_type=%s response_keys=%s", issue_id, issue_type, list(resp.keys()))

            ticketed_issue_ids.add(issue_id)

        logger.info("  - Done. Tickets created: %d", created_count)

    logger.info("All done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
