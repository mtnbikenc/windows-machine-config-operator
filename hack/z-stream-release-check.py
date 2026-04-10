#!/usr/bin/env python3
"""
z-stream-release-check.py — Determine which WMCO release branches need a z-stream release.

Run this before sprint planning to identify which release branches require action.
Exit code 1 means action is required; exit code 0 means all branches are clear.

Usage:
    python3 hack/z-stream-release-check.py
    python3 hack/z-stream-release-check.py --all              # include EOL branches
    python3 hack/z-stream-release-check.py --branch release-4.18  # single branch
    python3 hack/z-stream-release-check.py --json             # machine-readable output
    python3 hack/z-stream-release-check.py --connectivity     # test connectivity only

Optional environment variables:
    GITHUB_TOKEN    — GitHub personal access token (avoids API rate limiting)
    JIRA_API_TOKEN  — Jira API token for release ticket tracking
    JIRA_USERNAME   — Jira username / Atlassian account email (required with JIRA_API_TOKEN)

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
DATA SOURCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Red Hat Container Catalog
    WMCO operator images:  catalog.redhat.com → openshift4-wincw/windows-machine-config-rhel9-operator
    Base image:            catalog.redhat.com → ubi9/ubi-minimal

  Red Hat Support Policy Page
    GA dates per WMCO minor version:  access.redhat.com/support/policy/updates/openshift_operators

  GitHub API  (github.com/openshift/windows-machine-config-operator)
    Release branches, tags, PR metadata, branch-to-tag comparison

  Jira  (issues.redhat.com / redhat.atlassian.net)
    Open release Epics and Tasks in the WINC project

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CHECKS, DATA POINTS, AND THRESHOLDS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

1. SUPPORT WINDOW
   Source:    Red Hat support policy page (HTML-scraped version table)
   Data:      "Maintenance ends" date per WMCO minor version from the policy table
              (e.g. WMCO 10.18 → 2026-09-20). GA date is also scraped but only used
              as a fallback when "Maintenance ends" shows N/A or is not yet listed.
   Logic:     Primary: use the "Maintenance ends" date directly from the support page.
              Fallback: if not available, EOM = GA date + cutoff_months (approximate).
   Decision:  Branches where today > EOM are classified as EOL and excluded
              from recommendations (use --all to include them in output).
              Support notes show "~" prefix only when the fallback calculation is used.
   ⚙ Threshold:  "Maintenance ends" date from policy page (authoritative)
                 Fallback: --cutoff-months N (default 18) when page date is unavailable

2. PRE-RELEASE DETECTION
   Source:    GitHub branches + GitHub tags
   Data:      Existence of vMAJOR.MINOR.* tags for each release-X.Y branch
   Logic:     If a release-X.Y branch exists in GitHub but has no matching WMCO
              release tags, it is a pre-release branch still tracking master.
              OCP major → WMCO major mapping: ocp_major + 6  (OCP 4 → WMCO 10,
              OCP 5 → WMCO 11, etc.), so tags searched are v{ocp+6}.{minor}.*.
              OCP 4.X branches below 4.15 predate WMCO 10.x and are always legacy
              EOL regardless of tag presence (they used WMCO v1.x–v9.x tags).
              OCP 5.X+ branches have no legacy floor — without v11.X.* tags they
              are classified as pre-release.
   Decision:  Pre-release branches are shown in RELEASE BRANCHES but skipped in
              IMAGE HEALTH and SPRINT RECOMMENDATION — no action triggered.
   ⚙ Threshold:  OCP 4.x: minor >= 15 required for WMCO 10.x era (_WMCO10_MIN_OCP_MINOR)
                 OCP 5.x+: no minimum — all branches are checked for tags
                 Mapping: _ocp_to_wmco_major(ocp_major) = ocp_major + 6

3. IMAGE FRESHNESS GRADE
   Source:    Red Hat Container Catalog — freshness_grades[] on each image record
   Data:      Time-series of letter grades (A → B → C → D → F), each with a
              start_date and end_date. Current grade = entry spanning today.
   Columns:
     Grade       — Current letter grade of the published WMCO image
     Grade C Date — First date the image reaches grade C:
                    • For A/B images: the deadline — ship before this to stay healthy
                    • For C/D/F images: when the image first crossed the threshold
   Decision:  Grade below B (i.e. C, D, or F) triggers a release recommendation.
              Grade A or B is considered acceptable — no action on grade alone.
   ⚙ Threshold:  Grade must be A or B to be clear (change GRADE_ORDER / grade_is_below_b
                 to accept C if the team decides C is tolerable)

4. CVE VULNERABILITIES (published WMCO image)
   Source:    Red Hat Container Catalog — GET /images/id/{_id}/vulnerabilities
   Data:      All vulnerability records for the published WMCO image, tallied by
              the severity field: critical, important, moderate, low
   Columns:
     CVEs — Compact counts, e.g. "2C 1I 3M 5L" (zero-severity values omitted)
   Decision:  Critical OR Important CVEs trigger a release recommendation.
              Moderate and Low CVEs are displayed but do NOT trigger action —
              they are shown for completeness and future reference.
   ⚙ Threshold:  critical > 0 OR important > 0 → action needed
                 (change _has_actionable_cves() to also act on moderate if desired)

5. BASE IMAGE CVE STATUS (ubi9/ubi-minimal:latest)
   Source:    Red Hat Container Catalog — latest ubi9/ubi-minimal image + vulnerabilities
   Data:      CVE counts for the current base image that a new WMCO build would use
   Logic:     Compare base image total CVE count to the published WMCO image total:
                all ✓  — base has 0 CVEs: a new release resolves all WMCO CVEs
                ↓N     — base has N CVEs remaining: new release is a partial fix
                same ✗ — base has same or more CVEs: shipping alone won't help
   Column:    Base (in IMAGE HEALTH table)
   Decision:  Advisory only — does NOT itself trigger a release recommendation.
              Used to answer: "if we ship now, will the CVEs actually go away?"
   Note:      Branches 4.18–4.20 use FROM ubi9/ubi-minimal:latest (no digest pin)
              and always pick up the current base at build time. Branch 4.21+ has
              Mintmaker-managed digest pins updated via bot PRs.

6. UNRELEASED PULL REQUESTS
   Source:    GitHub Compare API (GET /compare/{tag}...{branch})
   Data:      Merge commits on the branch HEAD since the last release tag
   Filtering:
     Bot PRs excluded — identified by head-branch prefix:
       konflux/, mintmaker/, renovate/, dependabot/
     Bot PRs also excluded by GitHub login:
       openshift-bot, openshift-merge-robot, openshift-ci-robot
     cherry-pick robot PRs are KEPT — they carry real bug/CVE fixes
     Version-bump PRs excluded from action count — PRs whose title matches
       "Update version to X.Y.Z" (created by pre-release.sh). These are shown
       as [INFO] to indicate release prep has started, but do not themselves
       indicate a release is needed.
   Decision:  Any non-bot, non-version-bump team PR triggers a release recommendation.
   Note:      GitHub limits /compare to 250 commits. If ahead_by > 250, older PRs
              may be missing and the output will show a truncation warning.
   ⚙ Threshold:  team_prs > 0 (excluding bots and version bumps) → action needed

7. JIRA RELEASE TRACKING  (optional — requires JIRA_API_TOKEN + JIRA_USERNAME)
   Source:    Jira POST /rest/api/3/search/jql
   Query:     project = WINC AND issuetype in (Epic, Task)
              AND summary ~ "release" AND statusCategory != Done
   Data:      Open release Epics and Tasks, matched to branches via fixVersion
              format "WMCO 10.{minor}.{patch}" → OCP minor "4.{minor}"
   Display:   Shown as ↳ sub-lines under each branch in RELEASE BRANCHES and
              SPRINT RECOMMENDATION. Tasks are sorted before Epics (Tasks are
              the actionable, numbered work items).
   Decision:  Purely informational — Jira ticket state does NOT affect whether
              a release is recommended. A branch can need a release with no ticket
              open, or have a ticket open and still be clear on other checks.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
RELEASE RECOMMENDATION LOGIC
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

A branch appears in SPRINT RECOMMENDATION (action required) when ANY of the
following is true for an in-support, non-pre-release branch:

  ✗ UNRELEASED PRs  — one or more non-bot, non-version-bump team PRs have
                       merged since the last release tag
  ✗ IMAGE GRADE     — the published catalog image grade is below B (C, D, or F)
  ⚠ CVEs            — the published catalog image has Critical or Important CVEs

All three conditions are independent — any single one is sufficient.

Conditions that do NOT trigger a recommendation:
  • Moderate or Low CVEs only
  • A version-bump PR ("Update version to X.Y.Z") without other team PRs
  • Base image (ubi9/ubi-minimal) still having CVEs — this is advisory only
  • Jira tickets being open, in-progress, or absent
  • Grade A or B (regardless of CVEs)
"""

import argparse
import json
import os
import re
import sys
import time
from datetime import date, datetime, timedelta

import requests

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATALOG_API = (
    "https://catalog.redhat.com/api/containers/v1/repositories/"
    "registry/registry.access.redhat.com/repository/"
    "openshift4-wincw/windows-machine-config-rhel9-operator/images"
)
_CATALOG_UBI_MINIMAL_URL = (
    "https://catalog.redhat.com/api/containers/v1/repositories/"
    "registry/registry.access.redhat.com/repository/ubi9/ubi-minimal/images"
)
GITHUB_API = "https://api.github.com/repos/openshift/windows-machine-config-operator"
SUPPORT_PAGE = "https://access.redhat.com/support/policy/updates/openshift_operators"
JIRA_SEARCH_API = "https://redhat.atlassian.net/rest/api/3/search/jql"
# serverInfo is a GET endpoint that works without auth — used for connectivity probes.
_JIRA_SERVER_INFO_URL = "https://redhat.atlassian.net/rest/api/3/serverInfo"
JIRA_BROWSE = "https://issues.redhat.com/browse"

# OCP major → WMCO major offset. OCP 4 uses WMCO 10, OCP 5 uses WMCO 11, etc.
# All version derivations (tags, Jira fixVersions, support page lookups) use this.
_OCP_TO_WMCO_MAJOR_OFFSET = 6


def _ocp_to_wmco_major(ocp_major: int) -> int:
    """OCP 4 → WMCO 10, OCP 5 → WMCO 11, etc."""
    return ocp_major + _OCP_TO_WMCO_MAJOR_OFFSET


def _wmco_to_ocp_major(wmco_major: int) -> int:
    """WMCO 10 → OCP 4, WMCO 11 → OCP 5, etc."""
    return wmco_major - _OCP_TO_WMCO_MAJOR_OFFSET


# OCP 4.15 = WMCO 10.15 is the first v10.x release. OCP 4.X branches below this
# used WMCO v1.x–v9.x tags and will never match v10.x patterns; legacy EOL.
# There is no equivalent floor for OCP 5.x — all release-5.X branches are v11.x era.
_WMCO10_MIN_OCP_MINOR = 15

_VERSION_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")

# Merge commit subject: "Merge pull request #NNN from owner/branch-name"
_MERGE_COMMIT_RE = re.compile(r"^Merge pull request #(\d+) from \S+?/(.+)")

# Branch name prefixes that identify bot-generated bump PRs.
# Note: openshift-cherrypick-robot PRs use "cherry-pick-NNN-to-branch" branches
# and are intentionally NOT listed here — they carry real bug fixes.
_BOT_BRANCH_PREFIXES = (
    "konflux/",
    "mintmaker/",
    "renovate/",
    "dependabot/",
)

# GitHub user logins that are infrastructure bots (secondary check via PR API).
_BOT_LOGINS = frozenset({
    "openshift-bot",
    "openshift-merge-robot",
    "openshift-ci-robot",
})

# Jira item pattern extracted from PR titles (e.g. "WINC-1234", "OCPBUGS-5678")
_JIRA_RE = re.compile(r"\b(WINC|OCPBUGS|RFE)-\d+\b")

# Version bump PRs created by pre-release.sh (e.g. "Update version to 10.18.3").
# These are informational — they do not themselves indicate a release is needed.
_VERSION_BUMP_RE = re.compile(r"\bUpdate version to \d+\.\d+\.\d+", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Shared helpers (adapted from hack/verify-release.py)
# ---------------------------------------------------------------------------


def _github_headers() -> dict:
    token = os.environ.get("GITHUB_TOKEN")
    return {"Authorization": f"token {token}"} if token else {}


def _jira_auth() -> "tuple | None":
    """Return (username, api_token) for Jira Basic auth, or None if not configured."""
    token = os.environ.get("JIRA_API_TOKEN")
    user = os.environ.get("JIRA_USERNAME")
    return (user, token) if token and user else None


def _get(url, *, retries=3, delay=2, **kwargs) -> requests.Response:
    """Retry-enabled GET wrapper for transient network errors."""
    retries = max(1, retries)  # always attempt at least once
    last_exc = None
    for attempt in range(retries):
        try:
            return requests.get(url, **kwargs)
        except requests.exceptions.ConnectionError as exc:
            last_exc = exc
            if attempt < retries - 1:
                time.sleep(delay)
        except requests.RequestException:
            raise
    root = last_exc
    while root.__cause__ is not None:
        root = root.__cause__
    raise requests.exceptions.ConnectionError(
        f"Could not connect to {url.split('/')[2]}: {root}"
    ) from last_exc


def _fetch_images_from(api_url: str) -> list:
    """Fetch all image records from a catalog API endpoint, handling pagination."""
    images = []
    page = 0
    page_size = 100
    while True:
        params = {"page_size": page_size, "page": page, "sort_by": "creation_date[desc]"}
        resp = _get(api_url, params=params, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("data", [])
        if not batch:
            break
        images.extend(batch)
        if len(images) >= data.get("total", 0):
            break
        page += 1
    return images


def _version_from_tags(repos: list) -> str:
    """Extract x.y.z version string from a catalog image's repository tag list."""
    for repo in repos:
        for tag in repo.get("tags", []):
            m = _VERSION_TAG_RE.match(tag.get("name", ""))
            if m:
                return m.group(1)
    return ""


def _version_key(v: str) -> tuple:
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


# ---------------------------------------------------------------------------
# Support page dates
# ---------------------------------------------------------------------------

# Captures Version, GA date, and Maintenance ends date from the support policy
# page table. The title attribute holds the actual date string ("DD Mon YYYY").
# "Maintenance ends" is the authoritative end-of-support date for our purposes.
_SUPPORT_TABLE_ROW_RE = re.compile(
    r'data-label="Version"[^>]*>\s*([\d.]+)\s*</td>'
    r".*?data-label=\"General availability\"[^>]*title=\"([^\"]+)\""
    r".*?data-label=\"Maintenance ends\"[^>]*title=\"([^\"]+)\"",
    re.DOTALL,
)

# {wmco_minor: {"ga": "YYYY-MM-DD", "eom": "YYYY-MM-DD"|None}}
# e.g. {"10.18": {"ga": "2025-03-20", "eom": "2026-09-20"}}
_support_dates_cache = None


def _parse_support_date(raw: str) -> "str | None":
    """Parse a support page date string ("DD Mon YYYY") to "YYYY-MM-DD", or None."""
    raw = raw.strip()
    if not raw or raw.upper() in ("N/A", "TBD", ""):
        return None
    try:
        return datetime.strptime(raw, "%d %b %Y").strftime("%Y-%m-%d")
    except ValueError:
        return None


def _fetch_support_dates() -> dict:
    """
    Fetch the Windows Containers support policy page and return a mapping of
    WMCO minor version string (e.g. "10.18") to a dict with keys:
      "ga"  — General Availability date as "YYYY-MM-DD" (or None)
      "eom" — Maintenance ends date as "YYYY-MM-DD" (or None if N/A / not listed)
    Result is cached after the first fetch.
    """
    global _support_dates_cache
    if _support_dates_cache is not None:
        return _support_dates_cache

    try:
        resp = _get(SUPPORT_PAGE, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch support policy page: {exc}") from exc

    dates_map = {}
    for ver, raw_ga, raw_eom in _SUPPORT_TABLE_ROW_RE.findall(resp.text):
        dates_map[ver.strip()] = {
            "ga": _parse_support_date(raw_ga),
            "eom": _parse_support_date(raw_eom),
        }

    _support_dates_cache = dates_map
    return dates_map


# ---------------------------------------------------------------------------
# Catalog data
# ---------------------------------------------------------------------------


def fetch_catalog_versions() -> list:
    """
    Fetch all published WMCO operator image records from the Red Hat Container Catalog.
    Returns list of dicts with version, ocp_minor, published_date, freshness_grades,
    container_grades_msg, and build_commit. Deduplicated by version, sorted newest-first.
    """
    raw = _fetch_images_from(CATALOG_API)
    seen = {}
    for img in raw:
        repos = img.get("repositories", [])
        version = _version_from_tags(repos)
        if not version or version in seen:
            continue

        published_date = None
        for repo in repos:
            pd = repo.get("push_date")
            if pd:
                published_date = pd[:10]
                break

        freshness_grades = img.get("freshness_grades", [])

        cg = img.get("container_grades", {})
        container_grades_msg = cg.get("status_message", "") if isinstance(cg, dict) else ""

        labels = {
            lbl.get("name"): lbl.get("value")
            for lbl in img.get("parsed_data", {}).get("labels", [])
            if lbl.get("name")
        }
        build_commit = labels.get("org.opencontainers.image.revision", "")

        # WMCO 10.18.2 → OCP minor "4.18", WMCO 11.0.1 → OCP minor "5.0"
        parts = version.split(".")
        if len(parts) >= 2:
            wmco_major = int(parts[0])
            ocp_minor = f"{_wmco_to_ocp_major(wmco_major)}.{parts[1]}"
        else:
            ocp_minor = ""

        seen[version] = {
            "version": version,
            "image_internal_id": img.get("_id", ""),
            "ocp_minor": ocp_minor,
            "published_date": published_date,
            "freshness_grades": freshness_grades,
            "container_grades_msg": container_grades_msg,
            "build_commit": build_commit,
        }

    return sorted(seen.values(), key=lambda x: _version_key(x["version"]), reverse=True)


def get_latest_version_per_branch(all_versions: list) -> dict:
    """
    Group catalog versions by OCP minor and return only the latest per branch.
    Returns {"4.18": <version dict>, "4.19": <version dict>, ...}
    """
    by_branch = {}
    for v in all_versions:  # already sorted newest-first
        branch = v["ocp_minor"]
        if branch not in by_branch:
            by_branch[branch] = v
    return by_branch


# ---------------------------------------------------------------------------
# Support window
# ---------------------------------------------------------------------------


def annotate_support_status(latest_by_branch: dict, cutoff_months: int = 18) -> dict:
    """
    Annotate each branch entry with support status fields:
      - in_support: bool
      - ga_date: "YYYY-MM-DD" or None
      - eom_date: "YYYY-MM-DD" or None
      - support_note: human-readable status string

    The "Maintenance ends" date from the support policy page is used as the
    end-of-maintenance (EOM) date. If that date is not available for a version
    (e.g. not yet listed on the page), GA + cutoff_months is used as a fallback.
    """
    try:
        support_dates = _fetch_support_dates()
    except RuntimeError as exc:
        print(f"WARNING: Could not fetch support page dates: {exc}", file=sys.stderr)
        support_dates = {}

    today = date.today()

    result = {}
    for ocp_minor, data in latest_by_branch.items():
        # Support page uses WMCO minor version strings, e.g. "10.18", "11.0"
        ocp_parts = ocp_minor.split(".")
        wmco_major = _ocp_to_wmco_major(int(ocp_parts[0]))
        wmco_minor = f"{wmco_major}.{ocp_parts[1]}"
        dates = support_dates.get(wmco_minor, {})

        entry = dict(data)
        ga_date_str = dates.get("ga")
        eom_date_str = dates.get("eom")

        # Prefer the authoritative "Maintenance ends" date from the support page.
        # Fall back to GA + cutoff_months if the page doesn't have a date for this version.
        if eom_date_str:
            eom_date = datetime.strptime(eom_date_str, "%Y-%m-%d").date()
            in_support = today <= eom_date
            support_note = f"Active (maint. ends {eom_date_str})" if in_support else f"EOL ({eom_date_str})"
        elif ga_date_str:
            ga_date = datetime.strptime(ga_date_str, "%Y-%m-%d").date()
            eom_date = ga_date + timedelta(days=cutoff_months * 30)
            eom_date_str = eom_date.strftime("%Y-%m-%d")
            in_support = today <= eom_date
            support_note = f"Active (maint. ends ~{eom_date_str})" if in_support else f"EOL (~{eom_date_str})"
        else:
            eom_date_str = None
            in_support = True
            support_note = "Active (not yet on support page)"

        entry.update(
            {
                "ga_date": ga_date_str,
                "eom_date": eom_date_str,
                "in_support": in_support,
                "support_note": support_note,
            }
        )
        result[ocp_minor] = entry

    return result


# ---------------------------------------------------------------------------
# Image health
# ---------------------------------------------------------------------------

GRADE_ORDER = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4, "?": 5}


def get_current_freshness_grade(freshness_grades: list) -> tuple:
    """
    Return (current_grade, grade_expires_date) where grade_expires_date is "YYYY-MM-DD" or None.
    Finds the freshness_grades entry spanning today.
    """
    today_str = date.today().isoformat()
    for entry in freshness_grades:
        start = entry.get("start_date", "")[:10]
        end_raw = entry.get("end_date")
        end = end_raw[:10] if end_raw else None
        grade = entry.get("grade", "?")
        if start <= today_str and (end is None or today_str < end):
            return grade, end
    return "?", None


def grade_is_below_b(grade: str) -> bool:
    return GRADE_ORDER.get(grade, 5) > GRADE_ORDER["B"]


def get_grade_c_date(freshness_grades: list) -> "str | None":
    """
    Return the start_date of the first freshness grade entry at C or below.
    For images currently at A or B this is the deadline for shipping a new release
    before the grade falls below the acceptable threshold.
    For images already below B this is a past date showing when they first crossed it.
    """
    for entry in freshness_grades:
        g = entry.get("grade", "?")
        if GRADE_ORDER.get(g, 5) >= GRADE_ORDER["C"]:
            return entry.get("start_date", "")[:10]
    return None


# ---------------------------------------------------------------------------
# CVE / vulnerability data
# ---------------------------------------------------------------------------

_CVE_SEVERITIES = ("critical", "important", "moderate", "low")

_CATALOG_CVE_URL = "https://catalog.redhat.com/api/containers/v1/images/id/{image_id}/vulnerabilities"


def fetch_image_cves(image_internal_id: str) -> dict:
    """
    Fetch CVE vulnerability counts for a catalog image by its internal _id.
    Paginates the /vulnerabilities endpoint and tallies counts by severity.

    Returns:
        {"critical": N, "important": N, "moderate": N, "low": N, "total": N, "error": None}
    On fetch failure, returns zeroed counts with "error" set to the error string.
    """
    url = _CATALOG_CVE_URL.format(image_id=image_internal_id)
    counts = {s: 0 for s in _CVE_SEVERITIES}
    page = 0
    fetched = 0

    while True:
        try:
            resp = _get(url, params={"page_size": 100, "page": page}, timeout=30)
            resp.raise_for_status()
        except requests.RequestException as exc:
            return {**counts, "total": sum(counts.values()), "error": str(exc)}

        data = resp.json()
        batch = data.get("data", [])
        total = data.get("total", 0)

        for vuln in batch:
            severity = vuln.get("severity", "").lower()
            if severity in counts:
                counts[severity] += 1

        fetched += len(batch)
        if fetched >= total or not batch:
            break
        page += 1

    return {**counts, "total": sum(counts.values()), "error": None}


def _format_cve_counts(cve_counts: "dict | None") -> str:
    """
    Format CVE counts as a compact string showing only non-zero severities.
    E.g. {"critical":0,"important":1,"moderate":1,"low":1} → "1I 1M 1L"
    Returns "—" for no CVEs, "?" if the fetch errored.
    """
    if cve_counts is None:
        return "—"
    if cve_counts.get("error"):
        return "?"
    labels = {"critical": "C", "important": "I", "moderate": "M", "low": "L"}
    parts = [f"{cve_counts[s]}{labels[s]}" for s in _CVE_SEVERITIES if cve_counts.get(s)]
    return " ".join(parts) if parts else "—"


def _has_actionable_cves(cve_counts: "dict | None") -> bool:
    """Return True if the image has Critical or Important CVEs (warrants a release)."""
    if not cve_counts or cve_counts.get("error"):
        return False
    return cve_counts.get("critical", 0) > 0 or cve_counts.get("important", 0) > 0


_base_image_cves_cache = None


def fetch_base_image_cves() -> "dict | None":
    """
    Fetch CVE counts for the current ubi9/ubi-minimal:latest base image.
    Returns the same dict format as fetch_image_cves(), or None on failure.
    Result is cached — all WMCO branches share the same base image.

    This answers: 'would building a new release with the current base image fix the CVEs?'
    If the base image is clean (0 CVEs) and the published WMCO image has CVEs, then yes —
    the CVEs come from the old base, and a fresh build would resolve them.
    """
    global _base_image_cves_cache
    if _base_image_cves_cache is not None:
        return _base_image_cves_cache

    try:
        resp = _get(
            _CATALOG_UBI_MINIMAL_URL,
            params={"page_size": 1, "page": 0, "sort_by": "creation_date[desc]"},
            timeout=30,
        )
        resp.raise_for_status()
        batch = resp.json().get("data", [])
        if not batch:
            return None
        image_id = batch[0].get("_id", "")
        if not image_id:
            return None
        result = fetch_image_cves(image_id)
    except requests.RequestException as exc:
        result = {s: 0 for s in _CVE_SEVERITIES}
        result.update({"total": 0, "error": str(exc)})

    _base_image_cves_cache = result
    return result


def _base_image_fix_label(wmco_cves: "dict | None", base_cves: "dict | None") -> str:
    """
    Return a short label describing whether the current base image resolves the WMCO image CVEs.

    '—'      : WMCO image has no CVEs — nothing to fix
    'all ✓'  : base image is clean — a new release would resolve all CVEs
    '↓N'     : base still has N CVEs — new release is a partial fix
    'same ✗' : base image unchanged — a new release alone will NOT reduce CVEs
    '?'      : data unavailable
    """
    if wmco_cves is None or base_cves is None:
        return "?"
    if wmco_cves.get("error"):
        return "?"
    wmco_total = wmco_cves.get("total", 0)
    if wmco_total == 0:
        return "—"
    if base_cves.get("error"):
        return "?"
    base_total = base_cves.get("total", 0)
    if base_total == 0:
        return "all ✓"
    if base_total < wmco_total:
        return f"↓{base_total}"
    return "same ✗"


def _is_action_needed(results: list) -> bool:
    """Return True if any supported branch needs a z-stream release."""
    return any(
        not r.get("pre_release")
        and r.get("in_support")
        and (
            any(
                not pr.get("is_version_bump")
                for pr in (r.get("unreleased") or {}).get("team_prs", [])
            )
            or r.get("grade_warn")
            or _has_actionable_cves(r.get("cve_counts"))
        )
        for r in results
    )


# ---------------------------------------------------------------------------
# GitHub: release branches and tags
# ---------------------------------------------------------------------------

_RELEASE_BRANCH_RE = re.compile(r"^release-(\d+)\.(\d+)$")


def fetch_github_release_branches() -> list:
    """Fetch all release-X.Y branch names from GitHub, sorted by (major, minor)."""
    branches = []
    page = 1
    while True:
        url = f"{GITHUB_API}/branches"
        params = {"per_page": 100, "page": page}
        resp = _get(url, headers=_github_headers(), params=params, timeout=30)
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        for b in batch:
            if _RELEASE_BRANCH_RE.match(b.get("name", "")):
                branches.append(b["name"])
        if len(batch) < 100:
            break
        page += 1
    return sorted(branches, key=lambda b: tuple(int(x) for x in b[len("release-"):].split(".")))


def fetch_github_tags() -> dict:
    """Fetch all tags from GitHub. Returns {tag_name: commit_sha}."""
    tags = {}
    page = 1
    while True:
        url = f"{GITHUB_API}/tags"
        params = {"per_page": 100, "page": page}
        resp = _get(url, headers=_github_headers(), params=params, timeout=30)
        resp.raise_for_status()
        batch = resp.json()
        if not batch:
            break
        for t in batch:
            tags[t["name"]] = t["commit"]["sha"]
        if len(batch) < 100:
            break
        page += 1
    return tags


def find_latest_tag_for_branch(ocp_minor: str, all_tags: dict) -> "str | None":
    """
    Given an OCP minor version like "4.18" or "5.0", find the highest WMCO release tag
    (e.g. "v10.18.2" or "v11.0.1"). Returns None if no tags exist (pre-release branch).
    """
    ocp_parts = ocp_minor.split(".")
    wmco_major = _ocp_to_wmco_major(int(ocp_parts[0]))
    minor = ocp_parts[1]  # e.g. "18" or "0"
    pattern = re.compile(rf"^v{wmco_major}\.{minor}\.(\d+)$")
    candidates = []
    for tag_name in all_tags:
        m = pattern.match(tag_name)
        if m:
            candidates.append((int(m.group(1)), tag_name))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


# ---------------------------------------------------------------------------
# GitHub: unreleased pull requests
# ---------------------------------------------------------------------------


def _fetch_pr_details(pr_number: str) -> "dict | None":
    """
    Fetch a single PR's details from the GitHub API.
    Returns a dict with pr_number, title, author, is_bot, jira, merged_at.
    Returns None if the fetch fails.
    """
    url = f"{GITHUB_API}/pulls/{pr_number}"
    try:
        resp = _get(url, headers=_github_headers(), timeout=15)
        if resp.status_code != 200:
            return None
        pr = resp.json()
    except requests.RequestException:
        return None

    user = pr.get("user", {})
    login = user.get("login", "")
    # GitHub marks bots explicitly, or via [bot] suffix on login
    is_bot = (
        user.get("type") == "Bot"
        or login.endswith("[bot]")
        or login in _BOT_LOGINS
    )

    title = pr.get("title", "")
    jira_m = _JIRA_RE.search(title)
    return {
        "pr_number": pr_number,
        "title": title[:80],
        "author": login,
        "is_bot": is_bot,
        "jira": jira_m.group(0) if jira_m else "",
        "merged_at": (pr.get("merged_at") or "")[:10],
        "is_version_bump": bool(_VERSION_BUMP_RE.search(title)),
    }


def fetch_unreleased_prs(last_tag: str, branch: str) -> dict:
    """
    Use the GitHub Compare API to find merge commits on `branch` since `last_tag`,
    then fetch PR details for each non-bot merge.

    Only merge commits are considered (one per merged PR). Individual commits
    within a PR are intentionally ignored. Bot bump PRs (Konflux, Renovate,
    mintmaker, dependabot) are filtered out; cherry-pick robot PRs are kept.

    Returns:
        ahead_by     — total commit count between tag and branch HEAD
        total_prs    — number of merge commits found (team + bot)
        team_prs     — list of non-bot PR dicts: {pr_number, title, author, jira, merged_at}
        bot_filtered — count of bot PRs excluded
        truncated    — True if ahead_by > 250 (GitHub limit; older PRs may be missing)
        error        — error string or None
    """
    url = f"{GITHUB_API}/compare/{last_tag}...{branch}"
    resp = _get(url, headers=_github_headers(), timeout=30)

    if resp.status_code == 404:
        return {
            "ahead_by": 0, "total_prs": 0, "team_prs": [],
            "bot_filtered": 0, "truncated": False,
            "error": f"Compare not found: {last_tag}...{branch}",
        }
    resp.raise_for_status()

    data = resp.json()
    ahead_by = data.get("ahead_by", 0)
    raw_commits = data.get("commits", [])

    # Pass 1: identify merge commits and classify as bot vs. team by branch name
    team_pr_numbers = []
    bot_filtered = 0

    for c in raw_commits:
        subject = c.get("commit", {}).get("message", "").split("\n")[0]
        m = _MERGE_COMMIT_RE.match(subject)
        if not m:
            continue  # individual commit inside a PR — skip

        pr_number = m.group(1)
        head_branch = m.group(2)  # e.g. "konflux/references/release-4.18"

        if any(head_branch.startswith(p) for p in _BOT_BRANCH_PREFIXES):
            bot_filtered += 1
        else:
            team_pr_numbers.append(pr_number)

    # Pass 2: fetch full PR details for team PRs to get title and Jira item
    team_prs = []
    for pr_num in team_pr_numbers:
        details = _fetch_pr_details(pr_num)
        if not details:
            # Include with minimal info if the fetch fails
            team_prs.append({
                "pr_number": pr_num, "title": "(PR details unavailable)",
                "author": "", "is_bot": False, "jira": "", "merged_at": "",
                "is_version_bump": False,
            })
            continue
        if details.get("is_bot"):
            # Caught at API level (e.g. bot login not covered by branch prefix)
            bot_filtered += 1
        else:
            team_prs.append(details)

    return {
        "ahead_by": ahead_by,
        "total_prs": len(team_pr_numbers) + bot_filtered,
        "team_prs": team_prs,
        "bot_filtered": bot_filtered,
        "truncated": ahead_by > len(raw_commits),
        "error": None,
    }


# ---------------------------------------------------------------------------
# Jira release tracking
# ---------------------------------------------------------------------------

def fetch_jira_release_tickets() -> "dict | None":
    """
    Fetch open release Epics and Tasks from the WINC Jira project.

    fixVersions use the format "WMCO 10.{minor}.{patch}", which maps directly to
    OCP minor version 4.{minor}. Both Epics (containers) and Tasks (actionable,
    with numbered sub-tasks) are returned; Tasks are listed first per branch.

    Returns:
        {ocp_minor: [{"key", "summary", "status", "version", "issuetype", "url"}]}
        or None if JIRA_API_TOKEN / JIRA_USERNAME are not set.
        On fetch errors returns {} (empty dict, not None) so callers can distinguish
        "not configured" from "configured but failed".
    """
    auth = _jira_auth()
    if auth is None:
        return None

    jql = (
        'project = WINC AND issuetype in (Epic, Task) AND summary ~ "release" '
        "AND statusCategory != Done ORDER BY updated DESC"
    )
    payload = {
        "jql": jql,
        "fields": ["summary", "status", "fixVersions", "issuetype"],
        "maxResults": 50,
    }
    try:
        resp = requests.post(
            JIRA_SEARCH_API, auth=auth, json=payload,
            headers={"Accept": "application/json", "Content-Type": "application/json"},
            timeout=15,
        )
        resp.raise_for_status()
    except requests.RequestException as exc:
        print(f"WARNING: Jira fetch failed: {exc}", file=sys.stderr)
        return {}

    issues = resp.json().get("issues", [])
    result = {}

    for issue in issues:
        fields = issue.get("fields", {})
        for fv in fields.get("fixVersions", []):
            name = fv.get("name", "")  # e.g. "WMCO 10.19.2" or "WMCO 11.0.1"
            if not name.startswith("WMCO "):
                continue
            version_str = name[5:]  # "10.19.2" or "11.0.1"
            parts = version_str.split(".")
            if len(parts) != 3:
                continue
            try:
                wmco_major = int(parts[0])
            except ValueError:
                continue
            ocp_major = _wmco_to_ocp_major(wmco_major)
            if ocp_major < 4:  # skip any pre-OCP-4 fixVersions
                continue
            ocp_minor = f"{ocp_major}.{parts[1]}"
            result.setdefault(ocp_minor, []).append({
                "key": issue["key"],
                "summary": fields.get("summary", "").strip(),
                "status": fields.get("status", {}).get("name", ""),
                "version": version_str,
                "issuetype": fields.get("issuetype", {}).get("name", ""),
                "url": f"{JIRA_BROWSE}/{issue['key']}",
            })

    # Within each branch, sort Tasks before Epics (Tasks are the actionable items).
    for ocp_minor in result:
        result[ocp_minor].sort(key=lambda t: (0 if t["issuetype"] == "Task" else 1, t["key"]))

    return result


# ---------------------------------------------------------------------------
# Check runner
# ---------------------------------------------------------------------------


def run_checks(
    branch_data: dict,
    all_tags: dict,
    all_github_branches: list,
    include_eol: bool = False,
    filter_branch: "str | None" = None,
    jira_tickets: "dict | None" = None,
    base_image_cves: "dict | None" = None,
) -> list:
    """
    For each branch, collect image health and unreleased commit data.
    Pre-release branches (in GitHub but not in catalog) are included with status PRE-RELEASE.
    Returns list of result dicts sorted by OCP minor version.
    """
    results = []

    # Build the set of all branches to consider.
    # Branches in GitHub but NOT in the catalog fall into two categories:
    #   1. True pre-release: branch exists, but NO release tags exist yet
    #      (the newest branch, which still tracks master)
    #   2. Old EOL: branch exists, tags exist, but images used an older catalog
    #      (RHEL8-era branches before OCP 4.18 are not in the RHEL9 catalog)
    catalog_minors = set(branch_data)  # e.g. {"4.18", "4.19", "5.0"}
    github_minors = set()
    for b in all_github_branches:
        m = _RELEASE_BRANCH_RE.match(b)
        if m:
            github_minors.add(f"{m.group(1)}.{m.group(2)}")

    no_catalog_minors = github_minors - catalog_minors

    # Determine which no-catalog branches are truly pre-release (no tags) vs. old EOL.
    # OCP 4.X branches below 4.15 predate WMCO 10.x and are always legacy EOL.
    # OCP 5.X+ branches have no legacy floor — all are either pre-release or EOL by tags.
    true_pre_release = set()
    old_eol = set()
    for ocp_minor in no_catalog_minors:
        ocp_major = int(ocp_minor.split(".")[0])
        ocp_minor_int = int(ocp_minor.split(".")[1])
        if ocp_major == 4 and ocp_minor_int < _WMCO10_MIN_OCP_MINOR:
            # OCP 4.X before WMCO 10.x era — no v10.x tags exist by design
            old_eol.add(ocp_minor)
        else:
            tag = find_latest_tag_for_branch(ocp_minor, all_tags)
            if tag is None:
                true_pre_release.add(ocp_minor)
            else:
                old_eol.add(ocp_minor)

    # Combine: catalog branches + true pre-release branches
    # Old EOL branches (RHEL8-era) are only shown with --all
    all_minors = catalog_minors | true_pre_release
    if include_eol:
        all_minors |= old_eol

    for ocp_minor in sorted(all_minors, key=lambda v: tuple(int(x) for x in v.split("."))):
        branch_name = f"release-{ocp_minor}"

        if filter_branch and branch_name != filter_branch:
            continue

        # True pre-release branch: exists in GitHub, no release tags yet
        if ocp_minor in true_pre_release:
            results.append(
                {
                    "branch": branch_name,
                    "ocp_minor": ocp_minor,
                    "pre_release": True,
                    "in_support": False,
                    "support_note": "Pre-release (no catalog entry yet)",
                    "version": None,
                    "published_date": None,
                    "freshness_grade": None,
                    "grade_expires": None,
                    "grade_warn": False,
                    "grade_c_date": None,
                    "cve_counts": None,
                    "base_image_cves": base_image_cves,
                    "security_errata": "",
                    "security_warn": False,
                    "latest_tag": None,
                    "unreleased": None,
                    "jira_tickets": (jira_tickets or {}).get(ocp_minor, []),
                }
            )
            continue

        # Old EOL branch (RHEL8-era): has tags but no RHEL9 catalog entry
        if ocp_minor in old_eol:
            latest_tag = find_latest_tag_for_branch(ocp_minor, all_tags)
            results.append(
                {
                    "branch": branch_name,
                    "ocp_minor": ocp_minor,
                    "pre_release": False,
                    "in_support": False,
                    "support_note": "EOL (not in current catalog)",
                    "version": None,
                    "published_date": None,
                    "freshness_grade": None,
                    "grade_expires": None,
                    "grade_warn": False,
                    "grade_c_date": None,
                    "cve_counts": None,
                    "base_image_cves": base_image_cves,
                    "security_errata": "",
                    "security_warn": False,
                    "latest_tag": latest_tag,
                    "unreleased": None,
                    "jira_tickets": (jira_tickets or {}).get(ocp_minor, []),
                }
            )
            continue

        data = branch_data[ocp_minor]
        in_support = data.get("in_support", True)

        if not in_support and not include_eol:
            continue

        result = {
            "branch": branch_name,
            "ocp_minor": ocp_minor,
            "pre_release": False,
            "version": data["version"],
            "published_date": data.get("published_date"),
            "in_support": in_support,
            "support_note": data.get("support_note", "Unknown"),
        }

        # Image health
        grade, grade_expires = get_current_freshness_grade(data.get("freshness_grades", []))
        result["freshness_grade"] = grade
        result["grade_expires"] = grade_expires
        result["grade_warn"] = grade_is_below_b(grade)
        result["grade_c_date"] = get_grade_c_date(data.get("freshness_grades", []))

        # CVE vulnerabilities from the catalog Security tab
        image_internal_id = data.get("image_internal_id", "")
        if image_internal_id:
            result["cve_counts"] = fetch_image_cves(image_internal_id)
        else:
            result["cve_counts"] = {
                "critical": 0, "important": 0, "moderate": 0, "low": 0,
                "total": 0, "error": "no image ID",
            }
        result["base_image_cves"] = base_image_cves

        # Catalog health: unapplied package/layer updates.
        # security_errata / security_warn are not shown in the text report (CVE counts
        # from the /vulnerabilities endpoint are more actionable), but they are included
        # in the result dict so JSON consumers can access raw container_grades status.
        msg = data.get("container_grades_msg", "")
        has_errata = bool(msg and ("Critical" in msg or "Important" in msg))
        result["security_errata"] = msg
        result["security_warn"] = has_errata

        # Unreleased commits
        latest_tag = find_latest_tag_for_branch(ocp_minor, all_tags)
        result["latest_tag"] = latest_tag

        if latest_tag is None:
            result["unreleased"] = None
        else:
            try:
                result["unreleased"] = fetch_unreleased_prs(latest_tag, branch_name)
            except requests.RequestException as exc:
                result["unreleased"] = {
                    "ahead_by": 0, "total_prs": 0, "team_prs": [],
                    "bot_filtered": 0, "truncated": False, "error": str(exc),
                }

        result["jira_tickets"] = (jira_tickets or {}).get(ocp_minor, [])
        results.append(result)

    return results


# ---------------------------------------------------------------------------
# ANSI helpers (auto-disabled when not writing to a terminal)
# ---------------------------------------------------------------------------

_USE_COLOR = sys.stdout.isatty()


def _colored(code: str, s: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _USE_COLOR else s


def _red(s: str) -> str:
    return _colored("31", s)


def _yellow(s: str) -> str:
    return _colored("33", s)


def _green(s: str) -> str:
    return _colored("32", s)


def _bold(s: str) -> str:
    return _colored("1", s)


# ---------------------------------------------------------------------------
# Text report
# ---------------------------------------------------------------------------


def format_text_report(results: list, today_str: str) -> str:
    lines = []
    lines.append(_bold(f"WMCO Z-Stream Release Check — {today_str}"))
    lines.append("=" * 60)

    # ── Section 1: Release Branches ──────────────────────────────
    lines.append("")
    lines.append(_bold("RELEASE BRANCHES"))
    lines.append(f"{'Branch':<22} {'Last Release':<16} {'Published':<12} {'OCP':<7} Status")
    lines.append("-" * 90)

    for r in results:
        tag = r.get("latest_tag") or "--"
        pub = r.get("published_date") or "--"
        ocp = r.get("ocp_minor", "")
        note = r.get("support_note", "")

        if r.get("pre_release"):
            tag_col = "[PRE-RELEASE]"
            note_str = _yellow(note)
        elif not r.get("in_support"):
            tag_col = tag
            note_str = _yellow(note)
        else:
            tag_col = tag
            note_str = note

        lines.append(f"{r['branch']:<22} {tag_col:<16} {pub:<12} {ocp:<7} {note_str}")
        for ticket in r.get("jira_tickets", []):
            key = ticket["key"]
            version = ticket["version"]
            status = ticket["status"]
            itype = ticket["issuetype"]
            status_str = _yellow(status) if status == "In Progress" else status
            lines.append(f"  {'':>20}↳ {_bold(key)} v{version} ({itype}) — {status_str}")

    # ── Section 2: Image Health ───────────────────────────────────
    # Grade C Date: the first date this image reaches grade C.
    # For A/B images: deadline for a new release to maintain acceptable grade.
    # For C/D/F images: past date showing when the image crossed the threshold.
    # CVEs: counts from the catalog Security tab (C=Critical I=Important M=Moderate L=Low).
    # Base: whether the current ubi9/ubi-minimal base image resolves the CVEs.
    #   all ✓ = base is clean, new release fixes everything
    #   ↓N    = base still has N CVEs, partial fix
    #   same ✗= base unchanged, new release alone won't help
    lines.append("")
    lines.append(_bold("IMAGE HEALTH (Red Hat Container Catalog)"))
    lines.append(f"{'Version':<14} {'Grade':<8} {'Grade C Date':<14} {'CVEs':<14} {'Base':<10} Status")
    lines.append("-" * 72)

    for r in results:
        if r.get("pre_release") or not r.get("in_support"):
            continue

        version = r.get("version", "")
        grade = r.get("freshness_grade") or "?"
        grade_c_date = r.get("grade_c_date") or "--"
        cve_str = _format_cve_counts(r.get("cve_counts"))

        # Base image fix label — ANSI-safe padding (color applied before spaces).
        base_label = _base_image_fix_label(r.get("cve_counts"), r.get("base_image_cves"))
        base_pad = " " * (10 - len(base_label))
        if base_label == "all ✓":
            base_col = _green(base_label) + base_pad
        elif base_label.startswith("↓"):
            base_col = _yellow(base_label) + base_pad
        elif base_label == "same ✗":
            base_col = _red(base_label) + base_pad
        else:
            base_col = base_label + base_pad

        # Pad grade outside ANSI codes so terminal column width is correct.
        if r.get("grade_warn"):
            grade_col = _red(grade) + " " * (8 - len(grade))
            status_str = _red("✗")
        elif _has_actionable_cves(r.get("cve_counts")):
            grade_col = _yellow(grade) + " " * (8 - len(grade))
            status_str = _yellow("⚠")
        else:
            grade_col = _green(grade) + " " * (8 - len(grade))
            status_str = _green("✓")

        lines.append(f"v{version:<13} {grade_col} {grade_c_date:<14} {cve_str:<14} {base_col} {status_str}")

    # ── Section 3: Unreleased Pull Requests ──────────────────────
    lines.append("")
    lines.append(_bold("UNRELEASED PULL REQUESTS"))
    lines.append("-" * 60)

    for r in results:
        branch = r.get("branch", "")
        tag = r.get("latest_tag")

        if r.get("pre_release"):
            lines.append(f"{branch}: [PRE-RELEASE] — skipped")
            continue

        unreleased = r.get("unreleased")
        if not unreleased:
            lines.append(f"{branch}: no tag found — skipped")
            continue

        if unreleased.get("error"):
            lines.append(f"{branch} (since {tag}): ERROR — {unreleased['error']}")
            continue

        if not r.get("in_support"):
            continue

        team_prs = unreleased.get("team_prs", [])
        bot_filtered = unreleased.get("bot_filtered", 0)
        truncated = unreleased.get("truncated", False)

        action_prs = [pr for pr in team_prs if not pr.get("is_version_bump")]
        info_prs   = [pr for pr in team_prs if pr.get("is_version_bump")]
        action_count = len(action_prs)

        bot_note = f"  ({bot_filtered} bot bump{'s' if bot_filtered != 1 else ''} filtered)" if bot_filtered else ""

        if action_count == 0:
            # Zero action PRs — clean (version-bump-only PRs don't trigger a release)
            lines.append(f"{branch} (since {tag}): {_green('no team PRs  ✓')}{bot_note}")
        else:
            plural = "s" if action_count != 1 else ""
            lines.append(
                f"{branch} (since {tag}): {_yellow(f'{action_count} team PR{plural}  ⚠')}{bot_note}"
            )

        for pr in action_prs:
            jira = f"[{pr['jira']}] " if pr.get("jira") else ""
            lines.append(f"  PR #{pr['pr_number']}  {jira}{pr['title']}")
            lines.append(f"  {'':>6}by @{pr.get('author', '')}  {pr.get('merged_at', '')}")

        for pr in info_prs:
            jira = f"[{pr['jira']}] " if pr.get("jira") else ""
            lines.append(f"  PR #{pr['pr_number']}  [INFO] {jira}{pr['title']}")
            lines.append(f"  {'':>6}by @{pr.get('author', '')}  {pr.get('merged_at', '')}")
        if truncated:
            lines.append(
                f"  ⚠ {unreleased['ahead_by']} total commits exceeds limit — older PRs may be missing"
            )

    # ── Section 4: Sprint Recommendation ─────────────────────────
    # Grouped by branch: all reasons a release is needed are shown together.
    lines.append("")
    lines.append(_bold("SPRINT RECOMMENDATION"))
    lines.append("-" * 60)

    action_branches = []   # list of (result, action_prs, info_prs)
    clear_branch_names = []

    for r in results:
        if r.get("pre_release") or not r.get("in_support"):
            continue
        u = r.get("unreleased") or {}
        team_prs = u.get("team_prs", [])
        action_prs = [pr for pr in team_prs if not pr.get("is_version_bump")]
        info_prs   = [pr for pr in team_prs if pr.get("is_version_bump")]
        if action_prs or r.get("grade_warn") or _has_actionable_cves(r.get("cve_counts")):
            action_branches.append((r, action_prs, info_prs))
        else:
            clear_branch_names.append(r["branch"])

    if not action_branches:
        lines.append(_green("✓ No z-stream releases needed. All images healthy."))
    else:
        for r, action_prs, info_prs in action_branches:
            branch = r["branch"]
            tag = r.get("latest_tag") or "--"
            u = r.get("unreleased") or {}
            cve = r.get("cve_counts") or {}

            lines.append("")
            lines.append(_bold(branch))

            # Unreleased PRs
            if action_prs:
                bot_filtered = u.get("bot_filtered", 0)
                bot_note = f"  ({bot_filtered} bot filtered)" if bot_filtered else ""
                jiras = [pr["jira"] for pr in action_prs if pr.get("jira")]
                jira_str = f"  [{', '.join(jiras)}]" if jiras else ""
                count = len(action_prs)
                plural = "s" if count != 1 else ""
                lines.append(
                    f"  {_red('✗')} Unreleased PRs: {count} since {tag}{bot_note}{jira_str}"
                )
                for pr in action_prs:
                    jira = f"[{pr['jira']}] " if pr.get("jira") else ""
                    lines.append(f"      PR #{pr['pr_number']}  {jira}{pr['title']}")
                    lines.append(f"             @{pr.get('author', '')}  {pr.get('merged_at', '')}")
                if u.get("truncated"):
                    lines.append(
                        f"      ⚠ {u['ahead_by']} total commits exceeds limit — older PRs may be missing"
                    )

            # Image health
            if r.get("grade_warn"):
                grade = r.get("freshness_grade", "?")
                grade_c = r.get("grade_c_date") or "--"
                lines.append(
                    _red(f"  ✗ Image health: Grade {grade} — below threshold since {grade_c}")
                )

            # CVEs
            if _has_actionable_cves(cve):
                cve_parts = []
                if cve.get("critical"):
                    cve_parts.append(_red(f"{cve['critical']} Critical"))
                if cve.get("important"):
                    cve_parts.append(_yellow(f"{cve['important']} Important"))
                if cve.get("moderate"):
                    cve_parts.append(f"{cve['moderate']} Moderate")
                if cve.get("low"):
                    cve_parts.append(f"{cve['low']} Low")
                lines.append(f"  ⚠ CVEs: {', '.join(cve_parts)}")

                # Base image fix note — tells engineer whether shipping resolves the CVEs
                base_label = _base_image_fix_label(cve, r.get("base_image_cves"))
                if base_label == "all ✓":
                    lines.append(f"    {_green('↑ base image clean — releasing resolves all CVEs')}")
                elif base_label.startswith("↓"):
                    remaining = base_label[1:]
                    lines.append(
                        f"    {_yellow(f'↑ base has {remaining} CVE(s) remaining — releasing is a partial fix')}"
                    )
                elif base_label == "same ✗":
                    lines.append(
                        f"    {_red('↑ base image unchanged — releasing alone will NOT reduce CVEs')}"
                    )

            # Jira release tracking
            tickets = r.get("jira_tickets", [])
            if tickets:
                for ticket in tickets:
                    status_str = (
                        _yellow(ticket["status"]) if ticket["status"] == "In Progress"
                        else ticket["status"]
                    )
                    lines.append(
                        f"  → {_bold(ticket['key'])} v{ticket['version']}"
                        f" ({ticket['issuetype']}) — {status_str}"
                    )
            else:
                # Mention any version-bump PR as a signal that release prep has started
                hint = ""
                if info_prs:
                    m = re.search(r"\d+\.\d+\.\d+", info_prs[0]["title"])
                    if m:
                        hint = f"  (PR #{info_prs[0]['pr_number']} bumped version to {m.group(0)})"
                lines.append(f"  → No open release ticket{hint}")

    if clear_branch_names:
        lines.append("")
        lines.append(_green(f"✓ No action needed: {', '.join(clear_branch_names)}"))

    lines.append("")
    action_needed = bool(action_branches)
    status_label = "action required" if action_needed else "all clear"
    exit_code = 1 if action_needed else 0
    lines.append(f"Exit code: {exit_code} ({status_label})")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON report
# ---------------------------------------------------------------------------


def format_json_report(results: list, today_str: str) -> str:
    action_needed = _is_action_needed(results)
    return json.dumps(
        {"date": today_str, "action_required": action_needed, "branches": results},
        indent=2,
        default=str,
    )


# ---------------------------------------------------------------------------
# Connectivity check
# ---------------------------------------------------------------------------


def check_connectivity() -> bool:
    failures = []

    def probe(label: str, url: str, required: bool = True, **kwargs):
        try:
            resp = _get(url, timeout=8, allow_redirects=True, **kwargs)
            reachable = resp.status_code < 500
        except requests.RequestException as exc:
            print(f"  [FAIL] {label}: {exc}")
            if required:
                failures.append(label)
            return
        status = "[OK]  " if reachable else "[FAIL]"
        print(f"  {status} {label}" + ("" if reachable else f": HTTP {resp.status_code}"))
        if not reachable and required:
            failures.append(label)

    jira_auth = _jira_auth()

    print("Connectivity check")
    print("-" * 30)
    probe("Red Hat Container Catalog", "https://catalog.redhat.com/api/containers/v1/")
    probe("Red Hat Support Policy Page", SUPPORT_PAGE)
    probe("GitHub API", GITHUB_API, headers=_github_headers())
    if jira_auth:
        # Use serverInfo (GET, no auth required) to test reachability; auth validity
        # is implicitly verified when fetch_jira_release_tickets() runs later.
        probe("Jira (WINC project)", _JIRA_SERVER_INFO_URL, required=False)
    else:
        print("  [SKIP] Jira — set JIRA_API_TOKEN and JIRA_USERNAME to enable release tracking")
    print()

    if failures:
        print(
            f"ERROR: Cannot reach required service(s): {', '.join(failures)}",
            file=sys.stderr,
        )
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="Check which WMCO release branches need a z-stream release.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 hack/z-stream-release-check.py                        # in-support branches only
  python3 hack/z-stream-release-check.py --all                  # include EOL branches
  python3 hack/z-stream-release-check.py --branch release-4.18  # single branch
  python3 hack/z-stream-release-check.py --json                 # machine-readable output
  python3 hack/z-stream-release-check.py --connectivity         # test connectivity only
""",
    )
    parser.add_argument(
        "--all", "-a", action="store_true", help="Include EOL branches (default: in-support only)"
    )
    parser.add_argument(
        "--json", action="store_true", dest="json_output", help="Output machine-readable JSON"
    )
    parser.add_argument(
        "--branch",
        metavar="BRANCH",
        help="Check only this branch (e.g. release-4.18)",
    )
    parser.add_argument(
        "--cutoff-months",
        type=int,
        default=18,
        metavar="N",
        help="Support window in months (default: 18)",
    )
    parser.add_argument(
        "--connectivity", action="store_true", help="Test connectivity and exit"
    )
    args = parser.parse_args()

    if args.connectivity:
        sys.exit(0 if check_connectivity() else 2)

    if not check_connectivity():
        sys.exit(2)

    today_str = date.today().isoformat()

    print("Fetching WMCO image list from Red Hat Container Catalog...")
    try:
        all_catalog_versions = fetch_catalog_versions()
    except requests.RequestException as exc:
        print(f"ERROR: Failed to fetch catalog: {exc}", file=sys.stderr)
        sys.exit(2)

    if not all_catalog_versions:
        print("ERROR: No WMCO images found in catalog.", file=sys.stderr)
        sys.exit(2)

    latest_by_branch = get_latest_version_per_branch(all_catalog_versions)

    print("Fetching support window data...")
    branch_data = annotate_support_status(latest_by_branch, cutoff_months=args.cutoff_months)

    print("Fetching GitHub release branches...")
    try:
        all_github_branches = fetch_github_release_branches()
    except requests.RequestException as exc:
        print(f"WARNING: Could not fetch GitHub branches: {exc}", file=sys.stderr)
        all_github_branches = []

    print("Fetching GitHub tags...")
    try:
        all_tags = fetch_github_tags()
    except requests.RequestException as exc:
        print(f"ERROR: Failed to fetch GitHub tags: {exc}", file=sys.stderr)
        sys.exit(2)

    print("Fetching Jira release tickets...")
    jira_release_tickets = fetch_jira_release_tickets()
    if jira_release_tickets is None:
        print("  (Jira not configured — set JIRA_API_TOKEN and JIRA_USERNAME)")

    print("Fetching base image (ubi9/ubi-minimal) CVE status...")
    base_image_cves = fetch_base_image_cves()
    if base_image_cves and not base_image_cves.get("error"):
        total = base_image_cves.get("total", 0)
        print(f"  ubi9/ubi-minimal:latest — {total} CVE(s)")
    else:
        print("  (base image CVE fetch failed — base fix column will show '?')")

    print("Checking release branches and fetching CVE data...\n")
    results = run_checks(
        branch_data,
        all_tags,
        all_github_branches,
        include_eol=args.all,
        filter_branch=args.branch,
        jira_tickets=jira_release_tickets,
        base_image_cves=base_image_cves,
    )

    if not results:
        print(
            "No branches matched. Use --all to include EOL branches.",
            file=sys.stderr,
        )
        sys.exit(0)

    report = (
        format_json_report(results, today_str)
        if args.json_output
        else format_text_report(results, today_str)
    )
    print(report)

    sys.exit(1 if _is_action_needed(results) else 0)


if __name__ == "__main__":
    main()
