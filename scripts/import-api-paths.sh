#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
command -v python3 >/dev/null 2>&1 || {
    printf 'Error: python3 is required.\n' >&2
    exit 1
}

# Reuse the adjacent exporter's cloud discovery, backup and verification helpers.
python3 - "$script_dir" "$@" <<'PY'
import argparse
import copy
from datetime import datetime, timezone
from pathlib import Path
import re
import sys

SCRIPT_DIR = Path(sys.argv.pop(1))
sys.path.insert(0, str(SCRIPT_DIR))
import export_waf_rules as waf

RULE_NAME = "ApiPathAllowlistGuard"
RULE_PRIORITY = 50


def load_paths(path):
    paths = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), 1):
        if not re.match(r"^\s*\|\s*\d+\s*\|", line):
            continue
        columns = [column.strip() for column in line.strip().strip("|").split("|")]
        if len(columns) != 4 or not re.fullmatch(
            r"GET|HEAD|POST|OPTIONS|PUT|DELETE|PATCH", columns[1]
        ):
            raise ValueError(f"Invalid API table row at {path}:{number}")
        value = columns[2]
        if not re.fullmatch(r"`/[A-Za-z0-9_./~-]*`", value):
            raise ValueError(f"Only literal API paths are supported at {path}:{number}")
        value = value[1:-1]
        if "//" in value or any(part in {".", ".."} for part in value.split("/")):
            raise ValueError(f"Non-canonical API path at {path}:{number}")
        if value not in paths:
            paths.append(value)
    if not paths:
        raise ValueError(f"No API table rows found in {path}; refusing an empty allowlist.")
    return paths


def guard_rule(paths):
    patterns = [f"^{re.escape(path)}([?].*)?$" for path in paths]
    if any(len(pattern) > 256 for pattern in patterns):
        raise ValueError("An API path exceeds the 256-character regex limit.")
    if len(patterns) > 50:
        raise ValueError("At most 50 unique paths are supported by this single guard rule.")
    # Values within a condition are OR'ed; conditions are AND'ed:
    # NOT(group1) AND NOT(group2) ... blocks only paths outside the entire list.
    conditions = [{
        "matchVariables": [{"variableName": "RequestUri"}],
        "operator": "Regex",
        # This spelling is intentional: it is the ARM REST schema field name.
        "negationConditon": True,
        "matchValues": patterns[index:index + 10],
        "transforms": [],
    } for index in range(0, len(patterns), 10)]
    return {
        "name": RULE_NAME, "priority": RULE_PRIORITY, "ruleType": "MatchRule",
        "state": "Enabled", "action": "Block", "matchConditions": conditions,
    }


def build_body(target, paths):
    properties = waf.writable_properties(target)
    rules = [
        rule for rule in properties.get("customRules", [])
        if rule.get("name", "").casefold() != RULE_NAME.casefold()
    ]
    if len(rules) >= 100:
        raise ValueError("The policy has no room for an additional custom rule.")
    priorities = [rule.get("priority") for rule in rules]
    if any(type(value) is not int or not 1 <= value <= 100 for value in priorities):
        raise ValueError("Existing custom rules have invalid priorities.")
    if len(set(priorities)) != len(priorities):
        raise ValueError("Existing custom rules have duplicate priorities.")
    if RULE_PRIORITY in priorities:
        raise ValueError(
            f"Priority {RULE_PRIORITY} is already occupied by another custom rule; "
            "existing priorities will not be changed."
        )
    properties["customRules"] = [guard_rule(paths), *rules]
    properties["policySettings"].update(state="Enabled", mode="Prevention")
    return {
        "location": target["location"],
        "tags": copy.deepcopy(target.get("tags", {})),
        "properties": properties,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Import literal paths from api-path.md into an EXISTING AppGW WAF policy.",
        epilog=(
            "Default: preview only. --apply enables Prevention for the ENTIRE policy. "
            "Preserves existing rules; reserves custom rule name ApiPathAllowlistGuard. "
            "Guard priority is 50; fails if occupied by another rule. "
            "Earlier custom Allow rules can bypass the path allowlist. "
            "Paths are case-sensitive, without trailing-slash aliases; query strings are allowed. "
            "HTTP methods are NOT restricted. Encoded paths are not explicitly decoded. "
            "Requires az login, python3 and adjacent export_waf_rules.py. "
            "Uses the currently selected Azure cloud (including AzureChinaCloud). "
            "Does not attach policies: use WAF_v2 and associate this policy with the gateway/"
            "listeners serving the APIs. More-specific policies and redirects can bypass it. "
            "Internal-only endpoints in the input are included too; this is not authentication."
        ),
    )
    parser.add_argument("--subscription", required=True, help="Target subscription ID or name")
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--policy-name", required=True)
    parser.add_argument("--api-file", type=Path, default=SCRIPT_DIR / "api-path.md")
    parser.add_argument("--api-version", help="Override the cloud-advertised stable ARM API version")
    parser.add_argument("--output-dir", type=Path, help="New directory for backup and request JSON")
    parser.add_argument("--apply", action="store_true", help="Write changes after saving the backup")
    args = parser.parse_args(argv)
    paths = load_paths(args.api_file)
    guard_rule(paths)
    cloud, subscription, version = waf.azure_context(args.subscription, args.api_version)
    resource = waf.discover_policies(
        subscription, args.resource_group, [args.policy_name],
    )[0]
    url = waf.policy_url(cloud, resource["id"], version)
    target = waf.read_policy(url, subscription, resource["id"])
    if target["properties"].get("provisioningState") != "Succeeded" or not target.get("etag"):
        raise ValueError("Target policy is not ready or has no etag.")
    body = build_body(target, paths)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output_dir or Path("waf-api-allowlist") / stamp
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    waf.write_json(output / "before.json", target)
    waf.write_json(output / "request.json", body)
    waf.write_json(output / "context.json", {
        "cloud": cloud["name"], "subscriptionId": subscription,
        "resourceId": resource["id"], "url": url, "paths": paths,
    })
    print(f"Target: {resource['id']}")
    print(f"Backup and planned request: {output.resolve()}")
    print(f"{len(paths)} exact paths (all HTTP methods; query strings allowed):")
    for path in paths:
        print(f"  {path}")
    print(f"Other paths: Block, priority {RULE_PRIORITY}. Entire policy: Enabled / Prevention.")
    print("Existing rules and their priorities are preserved.")
    print("WARNING: This includes internal endpoints such as verify-reserve and settle.")
    print("WARNING: Policy association/overrides/redirects must be checked on the gateway.")
    if any(
        rule.get("action") == "Allow" and rule.get("state") != "Disabled"
        for rule in body["properties"]["customRules"]
    ):
        print("WARNING: Existing Allow rules still bypass managed inspection for matching requests.")
    if any(
        rule.get("action") == "Allow" and rule.get("state") != "Disabled"
        and rule["priority"] < RULE_PRIORITY
        for rule in body["properties"]["customRules"]
    ):
        print("WARNING: Custom Allow rules with priority below 50 can bypass the path allowlist.")
    if not args.apply:
        print("PREVIEW ONLY: no Azure changes. Re-run with --apply to update this policy.")
        return
    print("Applying; if interrupted, check the policy provisioning state before retrying.", flush=True)
    waf.az_json(
        "rest", "--method", "put", "--url", url, "--subscription", subscription,
        "--headers", f"If-Match={target['etag']}", "Content-Type=application/json",
        "--body", f"@{(output / 'request.json').resolve()}",
    )
    after = waf.wait_for_policy(url, subscription, resource["id"], 600)
    waf.write_json(output / "after.json", after)
    waf.verify_import(target, after, body, waf.rule_configuration(body["properties"]))
    print("VERIFIED: policy configuration updated. Gateway routing and live requests were NOT tested.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
PY
