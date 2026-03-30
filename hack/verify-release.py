#!/usr/bin/env python3
"""
verify-release.py — Verify WMCO release details against the Red Hat Container Catalog.

Usage:
    python3 hack/verify-release.py                     Check latest version only
    python3 hack/verify-release.py --version 10.18.2   Check a specific version
    python3 hack/verify-release.py --all               Check all shipped versions
"""

import argparse
import os
import re
import sys
from datetime import datetime
from urllib.parse import quote as urlquote
import requests
import yaml

CATALOG_API = (
    "https://catalog.redhat.com/api/containers/v1/repositories/"
    "registry/registry.access.redhat.com/repository/"
    "openshift4-wincw/windows-machine-config-rhel9-operator/images"
)
BUNDLE_CATALOG_API = (
    "https://catalog.redhat.com/api/containers/v1/repositories/"
    "registry/registry.access.redhat.com/repository/"
    "openshift4-wincw/windows-machine-config-operator-bundle/images"
)
ERRATA_BASE = "https://access.redhat.com/errata"
GITHUB_API = "https://api.github.com/repos/openshift/windows-machine-config-operator"
SUPPORT_PAGE = "https://access.redhat.com/support/policy/updates/openshift_operators"
GITLAB_API = (
    "https://gitlab.cee.redhat.com/api/v4/projects/releng%2Fadvisories/repository"
)
PAGE_SIZE = 100


def _fetch_images_from(api_url: str) -> list:
    """Fetch all image records from a catalog API endpoint, handling pagination."""
    images = []
    page = 0
    while True:
        params = {
            "page_size": PAGE_SIZE,
            "page": page,
            "sort_by": "creation_date[desc]",
        }
        resp = requests.get(api_url, params=params, timeout=30)
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


def fetch_all_images() -> list:
    """Fetch all operator image records from the catalog API."""
    return _fetch_images_from(CATALOG_API)


def fetch_bundle_commits() -> dict:
    """
    Fetch all bundle image records and return a mapping of version string
    (e.g. "10.21.1") to a dict with:
      - "commit":  build commit SHA from org.opencontainers.image.revision label
      - "digest":  sha256 image digest (e.g. "sha256:abc...")
    """
    raw = _fetch_images_from(BUNDLE_CATALOG_API)
    result = {}
    for img in raw:
        repos = img.get("repositories", [])
        version = _version_from_tags(repos)
        if not version or version in result:
            continue
        labels = {
            lbl["name"]: lbl["value"]
            for lbl in img.get("parsed_data", {}).get("labels", [])
        }
        commit = labels.get("org.opencontainers.image.revision", "")
        digest = img.get("image_id", "")  # "sha256:..."
        result[version] = {"commit": commit, "digest": digest}
    return result


def _version_key(v):
    try:
        return tuple(int(x) for x in v.split("."))
    except ValueError:
        return (0, 0, 0)


_VERSION_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")


def _version_from_tags(repos: list) -> str:
    """
    Find the x.y.z version string from a repository's tag list.
    Tags are named like 'v10.20.1', 'v10.20.1-1772659355', '06eb5cc', etc.
    Returns the stripped version (without leading 'v'), or "" if not found.
    """
    for repo in repos:
        for tag in repo.get("tags", []):
            m = _VERSION_TAG_RE.match(tag.get("name", ""))
            if m:
                return m.group(1)
    return ""


def extract_image_info(raw_images: list, bundle_commits: dict = None) -> list:
    """
    Extract version and advisory info from raw catalog API response.
    Deduplicates by version (multiple architectures may share a version).
    Returns list of dicts sorted newest-first:
        {"version": "10.18.2", "advisory_id": "RHBA-2025:1234"}
    """
    seen = {}
    for img in raw_images:
        repos = img.get("repositories", [])
        version = _version_from_tags(repos)
        if not version:
            continue
        if version in seen:
            continue
        advisory_id = None
        published_date = None
        for repo in repos:
            aid = repo.get("image_advisory_id")
            if aid:
                advisory_id = aid.strip()
            pd = repo.get("push_date")
            if pd:
                # Keep only the date portion (YYYY-MM-DD)
                published_date = pd[:10]
            if advisory_id and published_date:
                break
        labels = {
            lbl["name"]: lbl["value"]
            for lbl in img.get("parsed_data", {}).get("labels", [])
        }
        build_commit = labels.get("org.opencontainers.image.revision", "")
        bundle_info = (bundle_commits or {}).get(version, {})
        seen[version] = {
            "version": version,
            "advisory_id": advisory_id,
            "published_date": published_date,
            "build_commit": build_commit,
            "bundle_commit": bundle_info.get("commit", ""),
            "bundle_digest": bundle_info.get("digest", ""),
        }

    return sorted(seen.values(), key=lambda x: _version_key(x["version"]), reverse=True)


# ---------------------------------------------------------------------------
# Check functions
#
# Each check has the signature:
#   check_fn(image: dict, all_versions: list[str]) -> (passed: bool, message: str)
#
# `image`        — {"version": "x.y.z", "advisory_id": "RHBA-..."}
# `all_versions` — every WMCO version known from the catalog (for cross-checks)
# ---------------------------------------------------------------------------

_ISSUED_RE = re.compile(r'<dt>Issued:</dt>\s*<dd[^>]*>(.*?)</dd>', re.DOTALL)


def _errata_issued_date(html: str) -> str:
    """Extract the Issued date from errata page HTML, or '' if not found."""
    m = _ISSUED_RE.search(html)
    return m.group(1).strip() if m else ""


def check_advisory_version_match(image, all_versions):
    """
    Verify that the advisory for this image version:
      1. Mentions the correct WMCO version string.
      2. Does NOT mention any other known WMCO version string.
    Reports the errata issued date on success.
    """
    version = image["version"]
    advisory_id = image["advisory_id"]

    if not advisory_id:
        return False, f"No advisory found for version {version}"

    url = f"{ERRATA_BASE}/{advisory_id}"
    try:
        resp = requests.get(url, timeout=15, allow_redirects=True)
    except requests.RequestException as exc:
        return False, f"Failed to fetch advisory {advisory_id}: {exc}"

    if resp.status_code != 200:
        return False, f"Could not fetch advisory {advisory_id}: HTTP {resp.status_code}"

    text = resp.text
    issued = _errata_issued_date(text)
    issued_str = f", errata issued {issued}" if issued else ""

    # Check 1: correct version must be present
    if version not in text:
        return False, f"{advisory_id} does NOT mention version {version}"

    # Check 2: no OTHER known WMCO version should appear in the advisory
    wrong = sorted(v for v in all_versions if v != version and v in text)
    if wrong:
        return False, (
            f"{advisory_id} incorrectly references other WMCO versions: {', '.join(wrong)}"
        )

    return True, f"{advisory_id} mentions {version} and no other WMCO versions{issued_str}"


def check_git_tag_exists(image, all_versions):
    """
    Verify that a git tag matching the image version exists in the GitHub repo.
    Reports the commit hash of the tag on success.
    """
    version = image["version"]
    tag = f"v{version}"
    url = f"{GITHUB_API}/git/refs/tags/{tag}"

    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        resp = requests.get(url, headers=headers, timeout=15)
    except requests.RequestException as exc:
        return False, f"Failed to query GitHub for tag {tag}: {exc}"

    if resp.status_code == 404:
        return False, f"Tag {tag} not found in openshift/windows-machine-config-operator"
    if resp.status_code != 200:
        return False, f"GitHub API error for tag {tag}: HTTP {resp.status_code}"

    ref = resp.json()
    obj = ref.get("object", {})
    sha = obj.get("sha", "")
    obj_type = obj.get("type", "")

    # Annotated tags point to a tag object; resolve to the underlying commit.
    if obj_type == "tag":
        try:
            tag_resp = requests.get(obj.get("url", ""), headers=headers, timeout=15)
            tag_resp.raise_for_status()
            sha = tag_resp.json().get("object", {}).get("sha", sha)
        except requests.RequestException:
            pass  # Use the tag object sha as a fallback

    if not sha:
        return False, f"Could not resolve commit hash for tag {tag}"

    # The git tag is pushed when the bundle image is built, so compare against
    # the bundle image's build commit rather than the operator image's.
    build_commit = image.get("bundle_commit") or image.get("build_commit") or ""
    if not build_commit:
        return True, f"Tag {tag} found at commit {sha[:12]} (build commit unknown)"

    if not sha.startswith(build_commit) and not build_commit.startswith(sha):
        # Verify the build commit actually exists in this repo before reporting
        # a mismatch — rules out the image having been built from a different repo.
        commit_url = f"{GITHUB_API}/commits/{build_commit}"
        try:
            commit_resp = requests.get(commit_url, headers=headers, timeout=15)
        except requests.RequestException as exc:
            return False, (
                f"Tag {tag} points to {sha[:12]} but image was built from "
                f"{build_commit[:12]} (could not verify build commit in repo: {exc})"
            )
        if commit_resp.status_code == 404:
            return False, (
                f"Tag {tag} points to {sha[:12]} but image build commit "
                f"{build_commit[:12]} does not exist in openshift/windows-machine-config-operator "
                f"(may have been built from a different repository)"
            )
        if commit_resp.status_code != 200:
            return False, (
                f"Tag {tag} points to {sha[:12]} but image was built from "
                f"{build_commit[:12]} (GitHub API error verifying build commit: "
                f"HTTP {commit_resp.status_code})"
            )
        return False, (
            f"Tag {tag} points to {sha[:12]} but image was built from "
            f"{build_commit[:12]} (both commits confirmed in repo)"
        )

    return True, f"Tag {tag} commit {sha[:12]} matches image build commit"


_SUPPORT_TABLE_ROW_RE = re.compile(
    r'data-label="Version"[^>]*>\s*([\d.]+)\s*</td>'
    r'.*?data-label="General availability"[^>]*title="([^"]+)"',
    re.DOTALL,
)

_support_ga_cache = None  # {minor_version: "YYYY-MM-DD"}, e.g. {"10.20": "2025-10-22"}


def _fetch_support_ga_dates() -> dict:
    """
    Fetch the Windows Containers support policy page and return a mapping of
    minor version string (e.g. "10.20") to GA date (YYYY-MM-DD).
    Result is cached after the first fetch.
    """
    global _support_ga_cache
    if _support_ga_cache is not None:
        return _support_ga_cache

    try:
        resp = requests.get(SUPPORT_PAGE, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch support policy page: {exc}") from exc

    ga_map = {}
    for ver, raw_date in _SUPPORT_TABLE_ROW_RE.findall(resp.text):
        ver = ver.strip()
        try:
            # Parse "22 Oct 2025" → "2025-10-22"
            ga_map[ver] = datetime.strptime(raw_date.strip(), "%d %b %Y").strftime("%Y-%m-%d")
        except ValueError:
            ga_map[ver] = raw_date.strip()

    _support_ga_cache = ga_map
    return ga_map


def check_support_page_ga(image, all_versions):
    """
    Only applies to x.y.0 releases. Verifies that:
      1. The x.y minor version is listed on the Windows Containers support policy page.
      2. The listed General Availability date matches the image published date.
    Returns None (skip) for patch releases.
    """
    version = image["version"]
    major, minor, patch = version.split(".", 2)
    if patch != "0":
        return None, "only checked for x.y.0 releases"

    minor_ver = f"{major}.{minor}"
    image_published = image.get("published_date")

    try:
        ga_map = _fetch_support_ga_dates()
    except RuntimeError as exc:
        return False, str(exc)

    if minor_ver not in ga_map:
        return False, f"{minor_ver} not listed on the Windows Containers support policy page"

    ga_date = ga_map[minor_ver]
    if image_published and ga_date != image_published:
        try:
            delta = abs(
                (datetime.strptime(ga_date, "%Y-%m-%d") -
                 datetime.strptime(image_published, "%Y-%m-%d")).days
            )
        except ValueError:
            delta = None

        if delta == 1:
            return "warn", (
                f"{minor_ver} GA date on support page ({ga_date}) differs by one day "
                f"from image published date ({image_published})"
            )
        return False, (
            f"{minor_ver} GA date on support page ({ga_date}) does not match "
            f"image published date ({image_published})"
        )

    return True, f"{minor_ver} listed on support page with GA date {ga_date}"


# ---------------------------------------------------------------------------
# Advisory YAML helpers
# ---------------------------------------------------------------------------

_advisory_yaml_cache = {}  # advisory_id → parsed dict


def _fetch_advisory_yaml(advisory_id: str) -> dict:
    """
    Fetch and parse the advisory.yaml from the GitLab releng/advisories repo.
    Result is cached by advisory_id.
    Raises RuntimeError on fetch or parse failure.
    """
    if advisory_id in _advisory_yaml_cache:
        return _advisory_yaml_cache[advisory_id]

    # advisory_id format: "RHBA-2026:4787" → year=2026, number=4787
    try:
        year, number = advisory_id.split("-")[1].split(":")
    except (IndexError, ValueError) as exc:
        raise RuntimeError(f"Cannot parse advisory ID '{advisory_id}': {exc}") from exc

    path = f"data/advisories/windows-machine-conf-tenant/{year}/{number}/advisory.yaml"
    url = f"{GITLAB_API}/files/{urlquote(path, safe='')}/raw"
    try:
        resp = requests.get(url, params={"ref": "main"}, timeout=15)
        resp.raise_for_status()
    except requests.RequestException as exc:
        raise RuntimeError(f"Failed to fetch advisory YAML for {advisory_id}: {exc}") from exc

    try:
        data = yaml.safe_load(resp.text)
    except yaml.YAMLError as exc:
        raise RuntimeError(f"Failed to parse advisory YAML for {advisory_id}: {exc}") from exc

    _advisory_yaml_cache[advisory_id] = data
    return data


def check_advisory_yaml(image, all_versions):
    """
    Fetch the advisory YAML from the releng/advisories GitLab repo and verify:
      1. product_name = "Red Hat OpenShift for Windows Containers"
      2. synopsis contains the full x.y.z version string
      3. product_version = "{major}.{minor}"
      4. product_stream = "wmco-{major}.{minor}"
      5. All image purl fields contain "tag=v{version}-" (not a bare build number)
      6. Bundle image containerImage digest matches the catalog bundle digest
    All failures are accumulated and reported together.
    """
    advisory_id = image.get("advisory_id")
    if not advisory_id:
        return False, "no advisory ID found in catalog"

    version = image["version"]
    major, minor, _ = version.split(".", 2)
    minor_ver = f"{major}.{minor}"

    try:
        adv = _fetch_advisory_yaml(advisory_id)
    except RuntimeError as exc:
        return False, str(exc)

    spec = adv.get("spec", {})
    failures = []

    # Check 1: product_name
    expected_name = "Red Hat OpenShift for Windows Containers"
    actual_name = spec.get("product_name", "")
    if actual_name != expected_name:
        failures.append(f"product_name is '{actual_name}', expected '{expected_name}'")

    # Check 2: synopsis and topic both contain the full x.y.z version
    synopsis = spec.get("synopsis", "")
    if version not in synopsis:
        failures.append(f"synopsis does not contain version {version!r}: {synopsis!r}")

    topic = spec.get("topic", "")
    if version not in topic:
        failures.append(f"topic does not contain version {version!r}: {topic!r}")

    # Check 3: product_version = "x.y"
    # Compare as floats: unquoted YAML parses "10.20" as float 10.2, so string
    # comparison would incorrectly flag it as "10.2" != "10.20".
    actual_pver = spec.get("product_version", "")
    try:
        pver_match = float(actual_pver) == float(minor_ver)
    except (TypeError, ValueError):
        pver_match = False
    if not pver_match:
        failures.append(f"product_version is '{actual_pver}', expected '{minor_ver}'")

    # Check 4: product_stream = "wmco-x.y"
    expected_stream = f"wmco-{minor_ver}"
    actual_stream = spec.get("product_stream", "")
    if actual_stream != expected_stream:
        failures.append(f"product_stream is '{actual_stream}', expected '{expected_stream}'")

    # Check 5: each image's tags list must include a "v{version}-{build}" entry
    versioned_tag_prefix = f"v{version}-"
    for img_entry in spec.get("content", {}).get("images", []):
        component = img_entry.get("component", "unknown")
        tags = img_entry.get("tags", [])
        if not any(t.startswith(versioned_tag_prefix) for t in tags):
            failures.append(
                f"{component} tags {tags} missing a versioned tag starting with '{versioned_tag_prefix}'"
            )

    # Check 6: bundle image digest matches catalog
    bundle_digest = image.get("bundle_digest", "")
    if bundle_digest:
        for img_entry in spec.get("content", {}).get("images", []):
            if "operator-bundle" in img_entry.get("component", ""):
                adv_digest = img_entry.get("containerImage", "").split("@")[-1]
                # Normalize: catalog digest may or may not include "sha256:" prefix
                cat_digest = bundle_digest.lstrip("sha256:")
                adv_digest_bare = adv_digest.lstrip("sha256:")
                if adv_digest_bare and cat_digest and adv_digest_bare != cat_digest:
                    failures.append(
                        f"bundle digest in advisory ({adv_digest_bare[:16]}...) "
                        f"does not match catalog ({cat_digest[:16]}...)"
                    )
                break

    if failures:
        return False, f"advisory YAML ({advisory_id}): " + "; ".join(failures)

    return True, f"advisory YAML valid ({advisory_id})"


# ---------------------------------------------------------------------------
# Jira helpers
# ---------------------------------------------------------------------------

def _jira_auth():
    """Return (base_url, HTTPBasicAuth) or (None, None) if not configured."""
    from requests.auth import HTTPBasicAuth
    url = os.environ.get("JIRA_URL", "").rstrip("/")
    email = os.environ.get("JIRA_EMAIL", "")
    token = os.environ.get("JIRA_TOKEN", "")
    if not (url and email and token):
        return None, None
    return url, HTTPBasicAuth(email, token)


def _jira_search(base_url, auth, jql, fields) -> list:
    """Run a paginated Jira JQL search using the /search/jql API (cursor-based pagination)."""
    issues = []
    body = {"jql": jql, "fields": fields, "maxResults": 100}
    while True:
        resp = requests.post(
            f"{base_url}/rest/api/3/search/jql",
            auth=auth,
            timeout=15,
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("issues", [])
        issues.extend(batch)
        if data.get("isLast", True) or not batch:
            break
        body["nextPageToken"] = data["nextPageToken"]
    return issues


def _is_done(issue) -> bool:
    """Return True if the issue's status category is 'done'."""
    cat = issue["fields"]["status"].get("statusCategory", {})
    return cat.get("key") == "done"


_epic_cache = {}  # version -> epic issue dict (or None if not found)


def _get_epic(version, base_url, auth):
    """Return the Jira epic for this WMCO version, or None if not found. Cached."""
    if version in _epic_cache:
        return _epic_cache[version]
    fix_ver = f"WMCO {version}"
    epics = _jira_search(
        base_url, auth,
        jql=f'project = WINC AND issuetype = Epic AND fixVersion = "{fix_ver}"',
        fields=["summary", "status", "created"],
    )
    result = epics[0] if epics else None
    _epic_cache[version] = result
    return result


def _git_tag_sha(version) -> str:
    """Return the commit SHA for vX.Y.Z in the GitHub repo, or '' if not found."""
    tag = f"v{version}"
    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    try:
        resp = requests.get(f"{GITHUB_API}/git/refs/tags/{tag}", headers=headers, timeout=15)
        if resp.status_code != 200:
            return ""
        obj = resp.json().get("object", {})
        if obj.get("type") == "tag":
            r2 = requests.get(obj["url"], headers=headers, timeout=15)
            if r2.ok:
                return r2.json().get("object", {}).get("sha", "")
        return obj.get("sha", "")
    except requests.RequestException:
        return ""


def check_epic_status(image, all_versions):
    """
    Verify the Jira release epic for this version:
      - Epic must exist in the WINC project (matched by fixVersion "WMCO x.y.z").
      - If the epic is closed, all child issues must also be closed.
      - If the epic is closed, the git tag must have been pushed.
      - If the epic is closed and this is an x.y.0 release, the support page must be updated.
    Skipped if JIRA_URL / JIRA_EMAIL / JIRA_TOKEN are not set.
    """
    base_url, auth = _jira_auth()
    if not base_url:
        return None, "JIRA_URL / JIRA_EMAIL / JIRA_TOKEN not configured"

    version = image["version"]

    try:
        epic = _get_epic(version, base_url, auth)
    except requests.RequestException as exc:
        return False, f"Jira search failed: {exc}"

    if not epic:
        return False, f"No epic found in WINC project with fixVersion 'WMCO {version}'"

    epic_key = epic["key"]
    epic_status = epic["fields"]["status"]["name"]
    epic_url = f"{base_url}/browse/{epic_key}"

    if epic_status != "Closed":
        return False, f"{epic_key} status is '{epic_status}' — must be 'Closed' ({epic_url})"

    # Epic is Closed — verify all conditions were met before closing.
    failures = []

    # Condition 1: all child issues must be closed.
    try:
        children = _jira_search(
            base_url, auth,
            jql=f"parent = {epic_key}",
            fields=["summary", "status"],
        )
    except requests.RequestException as exc:
        return False, f"Failed to fetch child issues for {epic_key}: {exc}"

    open_children = [c for c in children if not _is_done(c)]
    if open_children:
        failures.append(f"child issue(s) not closed: {', '.join(c['key'] for c in open_children)}")

    # Condition 2: git tag must be pushed.
    if not _git_tag_sha(version):
        failures.append(f"git tag v{version} not pushed")

    # Condition 3: for x.y.0, support page must list the minor version.
    major, minor, patch = version.split(".", 2)
    if patch == "0":
        try:
            ga_map = _fetch_support_ga_dates()
        except RuntimeError:
            ga_map = {}
        if f"{major}.{minor}" not in ga_map:
            failures.append(f"support page not updated for {major}.{minor}")

    if failures:
        return False, f"{epic_key} closed prematurely — {'; '.join(failures)} ({epic_url})"

    child_summary = (
        f"all {len(children)} child issue(s) closed" if children else "no child issues"
    )
    return True, f"{epic_key} correctly closed ({child_summary}) ({epic_url})"


def check_cycle_time(image, all_versions):
    """
    Report (as INFO) the estimated release cycle time: from when release work started
    to when the image was published. Uses best-effort heuristics from Jira data.

    Fallback chain for start date:
      1. Earliest "In Progress" status transition on the Release child task.
      2. Creation date of the Release child task.
      3. Creation date of the epic itself.
    """
    base_url, auth = _jira_auth()
    if not base_url:
        return None, "JIRA_URL / JIRA_EMAIL / JIRA_TOKEN not configured"

    version = image["version"]
    published_date = image.get("published_date")
    if not published_date:
        return None, "image published date unknown"

    try:
        epic = _get_epic(version, base_url, auth)
    except requests.RequestException as exc:
        return None, f"Jira search failed: {exc}"

    if not epic:
        return None, f"no epic found for WMCO {version}"

    epic_key = epic["key"]
    epic_created = epic["fields"].get("created", "")

    # Find the Release child task (summary contains "release" but not "post release").
    try:
        children = _jira_search(
            base_url, auth,
            jql=f"parent = {epic_key}",
            fields=["summary", "status", "created"],
        )
    except requests.RequestException:
        children = []

    release_task = None
    for child in children:
        summary = child["fields"].get("summary", "").lower()
        if "release" in summary and "post release" not in summary:
            release_task = child
            break

    start_date = None
    source = None

    if release_task:
        task_key = release_task["key"]
        # Try to find the earliest "In Progress" transition in the changelog.
        try:
            cl_resp = requests.get(
                f"{base_url}/rest/api/3/issue/{task_key}",
                params={"expand": "changelog"},
                auth=auth,
                timeout=15,
            )
            cl_resp.raise_for_status()
            histories = cl_resp.json().get("changelog", {}).get("histories", [])
            for hist in sorted(histories, key=lambda h: h.get("created", "")):
                for item in hist.get("items", []):
                    if item.get("field") == "status" and item.get("toString") == "In Progress":
                        start_date = hist["created"][:10]
                        source = f"{task_key} moved to 'In Progress'"
                        break
                if start_date:
                    break
        except requests.RequestException:
            pass

        if not start_date:
            # Fallback: use task creation date.
            task_created = release_task["fields"].get("created", "")
            if task_created:
                start_date = task_created[:10]
                source = f"{task_key} created (no 'In Progress' transition found)"

    if not start_date and epic_created:
        # Final fallback: epic creation date.
        start_date = epic_created[:10]
        source = f"{epic_key} created (no Release child task found)"

    if not start_date:
        return None, f"could not determine release start date for {epic_key}"

    try:
        delta = (
            datetime.strptime(published_date, "%Y-%m-%d") -
            datetime.strptime(start_date, "%Y-%m-%d")
        ).days
    except ValueError:
        return None, f"date parse error ({start_date!r} or {published_date!r})"

    return "info", f"{delta} days ({source}: {start_date} → published {published_date})"


# Registry of checks: list of (check_fn, short_name) tuples.
# Add new checks here to extend the tool.
# A check may return (None, reason) to indicate it does not apply to a version;
# the runner will display [SKIP] and exclude it from pass/fail accounting.
CHECKS = [
    (check_advisory_version_match, "advisory_version_match"),
    (check_git_tag_exists, "git_tag_exists"),
    (check_support_page_ga, "support_page_ga"),
    (check_epic_status, "epic_status"),
    (check_advisory_yaml, "advisory_yaml"),
    (check_cycle_time, "cycle_time"),
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def run_checks(images_to_check: list, all_versions: list) -> bool:
    """
    Run all registered checks against images_to_check.
    all_versions is the full set of known WMCO versions (used for cross-checks).
    Returns True if every check passes, False otherwise.
    """
    results = []  # list of (image, check_name, passed, message)

    print("WMCO Release Verification")
    print("=" * 50)

    for img in images_to_check:
        version = img["version"]
        advisory_id = img["advisory_id"] or "no advisory"
        image_published = img.get("published_date") or "unknown"
        print(f"\nVersion {version}  [image published: {image_published}]  Advisory: {advisory_id}")

        for check_fn, check_name in CHECKS:
            passed, message = check_fn(img, all_versions)
            if passed is None:
                print(f"  [SKIP] {check_name}: {message}")
            elif passed == "info":
                print(f"  [INFO] {check_name}: {message}")
            elif passed == "warn":
                print(f"  [WARN] {check_name}: {message}")
            else:
                status = "PASS" if passed else "FAIL"
                print(f"  [{status}] {check_name}: {message}")
                results.append((version, check_name, passed))

    total_versions = len(images_to_check)
    failed_versions = set(
        version for version, _, passed in results if not passed
    )

    print("\n" + "=" * 50)
    passed_count = total_versions - len(failed_versions)
    print(f"Summary: {passed_count}/{total_versions} versions passed all checks")

    return len(failed_versions) == 0


def check_connectivity() -> bool:
    """
    Probe each external service used by this script.
    Prints [OK] or [FAIL] for each endpoint.
    Returns False if any required service is unreachable.
    """
    failures = []

    def probe(label, url, required=True, **kwargs):
        try:
            resp = requests.get(url, timeout=8, allow_redirects=True, **kwargs)
            reachable = resp.status_code < 500
        except requests.RequestException as exc:
            print(f"  [FAIL] {label}: {exc}")
            if required:
                failures.append(label)
            return
        if reachable:
            print(f"  [OK]   {label}")
        else:
            print(f"  [FAIL] {label}: HTTP {resp.status_code}")
            if required:
                failures.append(label)

    print("Connectivity check")
    print("-" * 30)

    gh_headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        gh_headers["Authorization"] = f"Bearer {token}"

    probe("Red Hat Container Catalog", "https://catalog.redhat.com/api/containers/v1/")
    probe("Red Hat Access (errata / support)", "https://access.redhat.com/")
    probe("GitHub API", GITHUB_API, headers=gh_headers)
    # Strip "/repository" suffix to probe the project API endpoint directly.
    probe("GitLab CEE", GITLAB_API.rsplit("/repository", 1)[0])

    jira_url = os.environ.get("JIRA_URL", "").rstrip("/")
    if jira_url:
        _, auth = _jira_auth()
        probe("Jira", f"{jira_url}/rest/api/3/serverInfo", auth=auth)
    else:
        print("  [SKIP] Jira (JIRA_URL not configured)")

    print()
    if failures:
        print(f"ERROR: Cannot reach required service(s): {', '.join(failures)}", file=sys.stderr)
        return False
    return True


def main():
    parser = argparse.ArgumentParser(
        description="Verify WMCO release details against the Red Hat Container Catalog.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""\
Examples:
  python3 hack/verify-release.py                     Check latest version only (default)
  python3 hack/verify-release.py --version 10.18.2   Check a specific version
  python3 hack/verify-release.py --all               Check all shipped versions
""",
    )
    parser.add_argument(
        "--version", "-v",
        metavar="X.Y.Z",
        help="Check only this specific version (e.g. 10.18.2)",
    )
    parser.add_argument(
        "--all", "-a",
        action="store_true",
        help="Check all shipped versions (default: latest only)",
    )
    args = parser.parse_args()

    if not check_connectivity():
        sys.exit(2)

    print("Fetching WMCO image list from Red Hat Container Catalog...")
    try:
        raw_images = fetch_all_images()
        bundle_commits = fetch_bundle_commits()
    except requests.RequestException as exc:
        print(f"ERROR: Failed to fetch image list: {exc}", file=sys.stderr)
        sys.exit(2)

    all_images = extract_image_info(raw_images, bundle_commits)
    if not all_images:
        print("ERROR: No WMCO images found in catalog.", file=sys.stderr)
        sys.exit(2)

    all_versions = [img["version"] for img in all_images]

    if args.version:
        images_to_check = [img for img in all_images if img["version"] == args.version]
        if not images_to_check:
            sample = ", ".join(all_versions[:10])
            print(
                f"ERROR: Version {args.version!r} not found in catalog.\n"
                f"Known versions (newest 10): {sample}",
                file=sys.stderr,
            )
            sys.exit(2)
    elif args.all:
        images_to_check = all_images
    else:
        # Default: check only the latest version
        images_to_check = [all_images[0]]

    passed = run_checks(images_to_check, all_versions)
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
