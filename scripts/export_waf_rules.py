#!/usr/bin/env python3
"""Export WAF policies, import rules, or create same-name target policies."""

import argparse
import copy
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from urllib.parse import quote


DEFAULT_SUBSCRIPTION = "38f40a54-772c-4d73-8f3a-f210d070a8f8"
DEFAULT_POLICIES = (
    "wafp-ladm-chinanorth3-prod",
    "wafp-ladm-chinanorth3-prod-portal",
)
RESOURCE_TYPE = "Microsoft.Network/ApplicationGatewayWebApplicationFirewallPolicies"
READ_ONLY_PROPERTIES = {
    "applicationGateways",
    "applicationGatewayForContainers",
    "httpListeners",
    "pathBasedRules",
    "provisioningState",
    "resourceState",
    "resourceGuid",
}


def az_json(*arguments):
    result = subprocess.run(
        ["az", *arguments, "--only-show-errors", "--output", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode:
        raise RuntimeError(
            f"Azure CLI failed (az {' '.join(arguments)}):\n{result.stderr.strip()}"
        )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise RuntimeError("Azure CLI returned invalid JSON.") from error


def select_api_version(provider, requested=None):
    versions = {
        version
        for resource in provider["resourceTypes"]
        if resource["resourceType"].casefold()
        == "applicationgatewaywebapplicationfirewallpolicies"
        for version in resource["apiVersions"]
    }
    if requested:
        if requested not in versions:
            raise RuntimeError(f"API version {requested} is not advertised by this cloud.")
        return requested
    stable = sorted(v for v in versions if re.fullmatch(r"\d{4}-\d{2}-\d{2}", v))
    if not stable:
        raise RuntimeError("No stable WAF policy API version was advertised by this cloud.")
    return stable[-1]


def find_policies(resources, names):
    selected = []
    for name in names:
        matches = [
            resource
            for resource in resources
            if resource["name"].casefold() == name.casefold()
        ]
        if not matches:
            raise RuntimeError(
                f"Policy not found: {name}. Check subscription, resource group and read permissions."
            )
        if len(matches) != 1:
            ids = "\n".join(resource["id"] for resource in matches)
            raise RuntimeError(
                f"Multiple policies named {name}; specify --resource-group:\n{ids}"
            )
        selected.append(matches[0])
    return selected


def writable_properties(policy):
    if policy.get("type", "").casefold() != RESOURCE_TYPE.casefold():
        raise RuntimeError("Unexpected resource type in WAF policy response.")
    properties = policy.get("properties")
    if not isinstance(properties, dict):
        raise RuntimeError(f"Missing policy properties: {policy.get('name')}")
    if not isinstance(properties.get("policySettings"), dict) or not isinstance(
        properties.get("managedRules", {}).get("managedRuleSets"), list
    ):
        raise RuntimeError(f"Incomplete WAF policy configuration: {policy.get('name')}")
    properties = copy.deepcopy(properties)
    for key in READ_ONLY_PROPERTIES:
        properties.pop(key, None)
    for rule_set in properties["managedRules"]["managedRuleSets"]:
        rule_set.pop("computedDisabledRules", None)
    return properties


def rule_configuration(properties):
    rules = {
        "customRules": copy.deepcopy(properties.get("customRules", [])),
        "managedRules": copy.deepcopy(properties["managedRules"]),
    }
    if not isinstance(rules["customRules"], list) or not isinstance(
        rules["managedRules"].get("managedRuleSets"), list
    ):
        raise RuntimeError("Invalid rule configuration.")
    for rule in rules["customRules"]:
        rule.pop("etag", None)
    for rule_set in rules["managedRules"]["managedRuleSets"]:
        rule_set.pop("computedDisabledRules", None)
        rule_set.setdefault("ruleGroupOverrides", [])
    rules["managedRules"].setdefault("exclusions", [])
    return rules


def migration_documents(policy, api_version):
    properties = writable_properties(policy)
    template = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "policyName": {"type": "string"},
            "location": {"type": "string"},
            "tags": {"type": "object"},
            "policyProperties": {"type": "object"},
        },
        "resources": [
            {
                "type": RESOURCE_TYPE,
                "apiVersion": api_version,
                "name": "[parameters('policyName')]",
                "location": "[parameters('location')]",
                "tags": "[parameters('tags')]",
                "properties": "[parameters('policyProperties')]",
            }
        ],
    }
    # Parameter files keep regexes beginning with "[" literal, not ARM expressions.
    parameters = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "policyName": {"value": policy["name"]},
            "location": {"value": policy["location"]},
            "tags": {"value": policy.get("tags", {})},
            "policyProperties": {"value": properties},
        },
    }
    return template, parameters


def write_json(path, value):
    with path.open("x", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write("\n")


def azure_context(subscription, api_version=None, require_china=False):
    if not shutil.which("az"):
        raise RuntimeError("Azure CLI is required. Install it, then run az login.")
    cloud = az_json("cloud", "show")
    if require_china and cloud["name"] != "AzureChinaCloud":
        raise RuntimeError(
            "Select China cloud and log in first:\n"
            "  az cloud set --name AzureChinaCloud\n"
            "  az login --use-device-code"
        )
    account = az_json("account", "show", "--subscription", subscription)
    if account["state"] != "Enabled":
        raise RuntimeError(f"Subscription is not enabled: {subscription}")
    subscription = account["id"]
    provider = az_json(
        "provider", "show", "--namespace", "Microsoft.Network",
        "--subscription", subscription,
    )
    return cloud, subscription, select_api_version(provider, api_version)


def list_policies(subscription, resource_group):
    command = [
        "resource", "list", "--subscription", subscription,
        "--resource-type", RESOURCE_TYPE,
    ]
    if resource_group:
        command.extend(["--resource-group", resource_group])
    return az_json(*command)


def discover_policies(subscription, resource_group, names):
    return find_policies(list_policies(subscription, resource_group), names)


def policy_url(cloud, resource_id, api_version):
    endpoint = cloud["endpoints"]["resourceManager"].rstrip("/")
    return f"{endpoint}{quote(resource_id, safe='/')}?api-version={api_version}"


def read_policy(url, subscription, resource_id):
    policy = az_json(
        "rest", "--method", "get", "--url", url, "--subscription", subscription,
    )
    if policy.get("id", "").casefold() != resource_id.casefold():
        raise RuntimeError(f"Unexpected resource ID returned for {resource_id}.")
    return policy


def export(args):
    cloud, subscription, api_version = azure_context(
        args.subscription, args.api_version, require_china=True,
    )
    selected = discover_policies(subscription, args.resource_group, args.policy_names)
    exports = []
    for resource in selected:
        policy = read_policy(
            policy_url(cloud, resource["id"], api_version), subscription, resource["id"],
        )
        template, parameters = migration_documents(policy, api_version)
        exports.append((policy, template, parameters))

    now = datetime.now(timezone.utc)
    output = args.output_dir or Path("waf-export") / now.strftime("%Y%m%dT%H%M%S%fZ")
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    manifest = {
        "exportedAtUtc": now.isoformat(),
        "cloud": cloud["name"],
        "subscriptionId": subscription,
        "apiVersion": api_version,
        "policies": [],
        "migrationNotes": [
            "For existing target policies, use --import-dir, NOT ARM deployment. "
            "Only customRules and managedRules are replaced; target-only rules are removed.",
            "Import defaults to preview. --apply backs up targets and writes changes.",
            "The create subcommand creates missing same-name policies with source "
            "settings/tags and skips existing policies without importing into them.",
            "Managed rules are preserved by rule-set type/version and all overrides, "
            "not by copying Microsoft's built-in rule implementation.",
            "ARM templates omit gateway/listener/path bindings. "
            "Rules-only import preserves the existing target bindings.",
            "Review environment-specific IPs, selectors, tags and policy mode before import.",
            "The target cloud/region must support the API version, rule-set versions "
            "and all enabled features. No automatic downgrade is performed.",
            "Deployment with an existing policy name can update/replace its configuration. "
            "Use a new name unless this is intended.",
        ],
    }
    for policy, template, parameters in exports:
        # Azure resource names cannot contain slashes; reject unsafe response names.
        name = policy["name"]
        if not re.fullmatch(r"[A-Za-z0-9_.()-]+", name) or name in {".", ".."}:
            raise RuntimeError(f"Unsafe policy name in response: {name!r}")
        directory = output / name
        directory.mkdir(mode=0o700)
        write_json(directory / "raw.json", policy)
        write_json(directory / "template.json", template)
        write_json(directory / "parameters.json", parameters)
        properties = parameters["parameters"]["policyProperties"]["value"]
        write_json(directory / "rules.json", rule_configuration(properties))
        manifest["policies"].append({
            "name": name,
            "sourceResourceId": policy["id"],
            "directory": name,
            "customRuleCount": len(properties.get("customRules", [])),
            "managedRuleSets": [
                {"type": item["ruleSetType"], "version": item["ruleSetVersion"]}
                for item in properties["managedRules"]["managedRuleSets"]
            ],
        })
    # Written last: only an export containing manifest.json is complete.
    write_json(output / "manifest.json", manifest)
    print(f"Exported {len(exports)} WAF policies to {output.resolve()}")
    print("Source policies were not changed. See manifest.json for migration limitations.")
    return output


def load_rules(directory, name):
    if not re.fullmatch(r"[A-Za-z0-9_.()-]+", name) or name in {".", ".."}:
        raise RuntimeError(f"Unsafe policy name: {name!r}")
    path = directory / name / "rules.json"
    if path.exists():
        properties = json.loads(path.read_text(encoding="utf-8"))
    else:
        # Older exports stored the same rules inside the ARM parameter file.
        path = directory / name / "parameters.json"
        properties = json.loads(path.read_text(encoding="utf-8"))[
            "parameters"
        ]["policyProperties"]["value"]
    return rule_configuration(properties)


def assert_configuration(expected, actual, path="policy"):
    """Allow service-added defaults but require every requested value and list item."""
    if isinstance(expected, dict) and isinstance(actual, dict):
        for key, value in expected.items():
            if key not in actual:
                if value is None or value == [] or value == {}:
                    continue
                raise RuntimeError(f"Verification failed: missing {path}.{key}")
            assert_configuration(value, actual[key], f"{path}.{key}")
    elif isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            raise RuntimeError(f"Verification failed: list length at {path}")
        for index, (left, right) in enumerate(zip(expected, actual)):
            assert_configuration(left, right, f"{path}[{index}]")
    elif expected != actual:
        raise RuntimeError(f"Verification failed: value differs at {path}")


def verify_import(before, after, body, rules):
    assert_configuration(body, {
        "location": after["location"],
        "tags": after.get("tags", {}),
        "properties": writable_properties(after),
    })
    actual_rules = rule_configuration(after["properties"])
    # Missing optional arrays mean empty, not "keep the target's old rules".
    for key in ("exclusions", "exceptions"):
        assert_configuration(
            rules["managedRules"].get(key, []),
            actual_rules["managedRules"].get(key, []),
            f"managedRules.{key}",
        )
    for key in (
        "applicationGateways", "applicationGatewayForContainers",
        "httpListeners", "pathBasedRules",
    ):
        old_ids = sorted(item["id"].casefold() for item in before["properties"].get(key, []))
        new_ids = sorted(item["id"].casefold() for item in after["properties"].get(key, []))
        if old_ids != new_ids:
            raise RuntimeError(f"Verification failed: target binding changed: {key}")


def wait_for_policy(url, subscription, resource_id, timeout):
    deadline = time.monotonic() + timeout
    while True:
        after = read_policy(url, subscription, resource_id)
        state = after["properties"].get("provisioningState")
        if state == "Succeeded":
            return after
        if state in {"Failed", "Canceled"}:
            raise RuntimeError(f"Target update failed: {resource_id} ({state})")
        if time.monotonic() >= deadline:
            raise RuntimeError(f"Timed out waiting for {resource_id}; check Azure before retrying.")
        time.sleep(5)


def import_rules(args):
    mappings = args.policy_map or [(name, name) for name in args.policy_names]
    for index, label in ((0, "source"), (1, "target")):
        names = [pair[index].casefold() for pair in mappings]
        if len(set(names)) != len(names):
            raise RuntimeError(f"Duplicate {label} policy names in mapping.")
    manifest = json.loads((args.import_dir / "manifest.json").read_text(encoding="utf-8"))
    available = {item["name"].casefold(): item["name"] for item in manifest["policies"]}
    if not all(source.casefold() in available for source, _ in mappings):
        raise RuntimeError("The export does not contain every requested policy.")
    mappings = [(available[source.casefold()], target) for source, target in mappings]
    source_rules = {
        source: load_rules(args.import_dir, source) for source, _ in mappings
    }
    # Use the source API version, never silently downgrade features in the target cloud.
    cloud, subscription, api_version = azure_context(
        args.subscription, args.api_version or manifest["apiVersion"],
    )
    if subscription.casefold() == manifest["subscriptionId"].casefold():
        raise RuntimeError("Target subscription must differ from the source subscription.")
    targets = discover_policies(
        subscription, args.resource_group, [target for _, target in mappings],
    )
    plans = []
    for (name, _), resource in zip(mappings, targets):
        url = policy_url(cloud, resource["id"], api_version)
        target = read_policy(url, subscription, resource["id"])
        if target["properties"].get("provisioningState") != "Succeeded" or not target.get("etag"):
            raise RuntimeError(f"Target is not ready or has no etag: {name}")
        properties = writable_properties(target)
        properties.update(source_rules[name])
        if "exceptions" in target["properties"]["managedRules"]:
            properties["managedRules"].setdefault("exceptions", [])
        body = {
            "location": target["location"],
            "tags": copy.deepcopy(target.get("tags", {})),
            "properties": properties,
        }
        plans.append((name, url, target, body))

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    backup = args.backup_dir or Path("waf-import") / timestamp
    backup.mkdir(mode=0o700, parents=True, exist_ok=False)
    for name, url, target, body in plans:
        directory = backup / name
        directory.mkdir(mode=0o700)
        write_json(directory / "before.json", target)
        write_json(directory / "request.json", body)
        print(
            f"{'APPLY' if args.apply else 'PREVIEW'}: "
            f"{name} -> {target['id']} (replace ALL rules)"
        )
    write_json(backup / "plan.json", {
        "targetSubscriptionId": subscription,
        "targetCloud": cloud["name"],
        "apiVersion": api_version,
        "applyRequested": args.apply,
        "policies": [target["id"] for _, _, target, _ in plans],
        "policyMappings": [
            {
                "sourcePolicyName": name,
                "targetPolicyName": target["name"],
                "targetResourceId": target["id"],
                "backupDirectory": name,
            }
            for name, _, target, _ in plans
        ],
        "warning": "Not transactional. Do not edit/delete target policies concurrently. "
                   "before.json is the backup; after.json marks a verified update.",
    })
    print(f"Target backups and request previews: {backup.resolve()}")
    if not args.apply:
        print("Preview only: no Azure writes. Use --apply to replace target rules.")
        return backup

    print("Applying sequentially; failures stop immediately. No automatic rollback.")
    for name, url, target, body in plans:
        latest = read_policy(url, subscription, target["id"])
        if latest.get("etag") != target["etag"]:
            raise RuntimeError(f"Target changed after backup; aborting: {name}")
        request = backup / name / "request.json"
        az_json(
            "rest", "--method", "put", "--url", url,
            "--subscription", subscription, "--body", f"@{request.resolve()}",
            "--headers", "Content-Type=application/json", f"If-Match={target['etag']}",
        )
        after = wait_for_policy(url, subscription, target["id"], args.timeout)
        verify_import(target, after, body, source_rules[name])
        write_json(backup / name / "after.json", after)
        print(
            "Verified rules and preserved target settings/bindings: "
            f"{name} -> {target['name']}"
        )
    print("Both selected policies have been updated and verified." if len(plans) == 2
          else "Selected policies have been updated and verified.")
    return backup


def create_policies(args):
    manifest = json.loads((args.import_dir / "manifest.json").read_text(encoding="utf-8"))
    available = {item["name"].casefold(): item["name"] for item in manifest["policies"]}
    sources = []
    for selected in args.policy_names:
        if selected.casefold() not in available:
            raise RuntimeError(f"The export does not contain policy: {selected}")
        name = available[selected.casefold()]
        rules = load_rules(args.import_dir, name)
        parameters = json.loads(
            (args.import_dir / name / "parameters.json").read_text(encoding="utf-8")
        )["parameters"]
        properties = writable_properties({
            "type": RESOURCE_TYPE, "name": name,
            "properties": parameters["policyProperties"]["value"],
        })
        properties.update(rules)
        sources.append((name, {
            "location": args.location or parameters["location"]["value"],
            "tags": parameters["tags"]["value"],
            "properties": properties,
        }))
    cloud, subscription, api_version = azure_context(
        args.subscription, args.api_version or manifest["apiVersion"],
    )
    if subscription.casefold() == manifest["subscriptionId"].casefold():
        raise RuntimeError("Target subscription must differ from the source subscription.")
    group = az_json(
        "group", "show", "--name", args.resource_group, "--subscription", subscription,
    )
    existing = {item["name"].casefold() for item in list_policies(subscription, group["name"])}
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    output = args.output_dir or Path("waf-create") / timestamp
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    plans = []
    entries = []
    for name, body in sources:
        resource_id = (
            f"{group['id']}/providers/{RESOURCE_TYPE}/{name}"
        )
        skip = name.casefold() in existing
        entries.append({
            "name": name, "targetResourceId": resource_id,
            "action": "skip-existing" if skip else "create",
        })
        if skip:
            print(f"SKIP existing policy (unchanged): {resource_id}")
            continue
        directory = output / name
        directory.mkdir(mode=0o700)
        write_json(directory / "request.json", body)
        plans.append((name, resource_id, body))
        print(f"{'CREATE' if args.apply else 'PREVIEW create'}: {resource_id}")
    write_json(output / "plan.json", {
        "targetSubscriptionId": subscription, "targetCloud": cloud["name"],
        "apiVersion": api_version, "applyRequested": args.apply, "policies": entries,
        "warning": "Not transactional; failures may leave created policies. "
                   "No automatic rollback. Do not create/edit/delete targets concurrently. "
                   "Created policies are not bound to any gateway.",
    })
    print(f"Creation requests and plan: {output.resolve()}")
    if not args.apply:
        print("Preview only: no Azure writes. Use create ... --apply to create missing policies.")
        return output
    for name, resource_id, body in plans:
        # Recheck just before PUT, and request create-only semantics as an extra guard.
        current = list_policies(subscription, group["name"])
        if any(item["name"].casefold() == name.casefold() for item in current):
            write_json(output / name / "skipped.json", {"reason": "Policy now exists."})
            print(f"SKIP policy created since preview (unchanged): {resource_id}")
            continue
        url = policy_url(cloud, resource_id, api_version)
        request = output / name / "request.json"
        az_json(
            "rest", "--method", "put", "--url", url,
            "--subscription", subscription, "--body", f"@{request.resolve()}",
            "--headers", "Content-Type=application/json", "If-None-Match=*",
        )
        after = wait_for_policy(url, subscription, resource_id, args.timeout)
        verify_import(
            {"properties": {}}, after, body, rule_configuration(body["properties"]),
        )
        write_json(output / name / "after.json", after)
        print(f"Created and verified all rules/settings/tags: {resource_id}")
    print("Creation finished; existing policies were skipped. Bind new policies separately.")
    return output


def parse_policy_mapping(value):
    source, separator, target = value.partition("=")
    if not separator or not source.strip() or not target.strip() or "=" in target:
        raise argparse.ArgumentTypeError("Use SOURCE_POLICY=TARGET_POLICY with nonempty names.")
    return source.strip(), target.strip()


def parse_args():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Before exporting (interactive login; no password in this script):
  az cloud set --name AzureChinaCloud
  az login --use-device-code
  python3 export_waf_rules.py

Output per policy: raw.json, rules.json, template.json, parameters.json.
An export is complete only when manifest.json exists.
Requires read access to the subscription's resource inventory and WAF policies.
Exports contain internal rule configuration; keep the directory private.

Import ALL rules into existing same-name policies (no policy creation):
  python3 export_waf_rules.py --import-dir waf-export/TIMESTAMP \\
    --subscription TARGET_SUB --resource-group TARGET_RG
  python3 export_waf_rules.py --import-dir waf-export/TIMESTAMP \\
    --subscription TARGET_SUB --resource-group TARGET_RG --apply

For different policy names, repeat --policy-map SOURCE=TARGET:
  python3 export_waf_rules.py --import-dir waf-export/TIMESTAMP \\
    --subscription TARGET_SUB --resource-group TARGET_RG \\
    --policy-map wafp-ladm-chinanorth3-prod=wafp-test \\
    --policy-map wafp-ladm-chinanorth3-prod-portal=wafp-test-portal

Mappings select only the listed source policies and must be one-to-one.
Without mappings, imports use identical source/target names as before.
Backup subdirectories use source names; plan.json records the target mapping.
Default is preview only. --apply replaces customRules and managedRules, including
rule-set versions, overrides, exclusions and exceptions. Target-only rules are
removed. Target location, tags, policySettings, tier and gateway bindings are
preserved. Existing exports without rules.json are also supported.
Log in to the target cloud before importing. Target must support the source API
and rule features. Backups and request previews are saved under waf-import/.
Updates are sequential, not transactional; a failure can leave partial changes.
Do not edit/delete target policies concurrently. Inspect before.json/after.json
after a failure; there is no automatic rollback.
Do NOT use template.json for rules-only import: it also changes policy settings.

Create missing same-name policies, copying ALL rules, settings and tags:
  python3 export_waf_rules.py create --import-dir waf-export/TIMESTAMP \\
    --subscription TARGET_SUB --resource-group TARGET_RG --location chinanorth3
Add --apply to create. Existing policies are skipped, NOT updated.
The target resource group must exist. Without --location, use each source region.
New policies have no gateway bindings. Requests/results are saved under waf-create/.
""",
    )
    parser.add_argument("--subscription", help="Required target subscription for import.")
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument(
        "--policy-names", nargs="+", default=list(DEFAULT_POLICIES),
        help="Export names or same-name import selection; defaults to the two source policies.",
    )
    selection.add_argument(
        "--policy-map", action="append", type=parse_policy_mapping,
        metavar="SOURCE=TARGET",
        help="Import only: source-to-target mapping; repeat for each pair.",
    )
    parser.add_argument("--resource-group", help="Limit discovery; required for duplicate names.")
    parser.add_argument("--output-dir", type=Path, help="New directory; existing paths are rejected.")
    parser.add_argument("--api-version", help="Override automatic latest stable API selection.")
    parser.add_argument("--import-dir", type=Path, help="Import rules from a complete export.")
    parser.add_argument("--apply", action="store_true", help="Write rules; import otherwise previews.")
    parser.add_argument("--backup-dir", type=Path, help="New directory for import backups/preview.")
    parser.add_argument("--timeout", type=int, default=600, help="Import wait timeout per policy in seconds.")
    commands = parser.add_subparsers(dest="command")
    create = commands.add_parser(
        "create",
        help="Create missing same-name policies with all source rules/settings/tags; skip existing.",
        description="Preview by default. Existing policies are skipped without importing rules. "
                    "New policies have no gateway bindings. Creation is not transactional; "
                    "do not create/edit/delete the target policies concurrently.",
    )
    create.add_argument("--import-dir", type=Path, required=True, help="Complete source export.")
    create.add_argument("--subscription", required=True, help="Target subscription.")
    create.add_argument("--resource-group", required=True, help="Existing target resource group.")
    create.add_argument("--location", help="Target region; defaults to each policy's source region.")
    create.add_argument("--policy-names", nargs="+", default=list(DEFAULT_POLICIES))
    create.add_argument("--api-version", help="Override the source export API version.")
    create.add_argument("--apply", action="store_true", help="Create missing policies; otherwise preview.")
    create.add_argument("--output-dir", type=Path, help="New directory for creation plan/results.")
    create.add_argument("--timeout", type=int, default=600, help="Wait timeout per policy in seconds.")
    args = parser.parse_args()
    if args.command == "create":
        if args.policy_map or args.backup_dir:
            parser.error("create does not support --policy-map or --backup-dir.")
    if args.import_dir and not args.subscription:
        parser.error("--subscription is required for import; no implicit target is allowed.")
    if not args.import_dir and (args.apply or args.backup_dir or args.policy_map):
        parser.error("--apply, --backup-dir and --policy-map require --import-dir.")
    if args.timeout <= 0:
        parser.error("--timeout must be positive.")
    if not args.subscription:
        args.subscription = DEFAULT_SUBSCRIPTION
    if len({name.casefold() for name in args.policy_names}) != len(args.policy_names):
        parser.error("--policy-names must not contain duplicate names.")
    return args


def main():
    os.umask(0o077)
    try:
        args = parse_args()
        if args.command == "create":
            create_policies(args)
        elif args.import_dir:
            import_rules(args)
        else:
            export(args)
    except (RuntimeError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"WAF operation failed: {error}", file=sys.stderr)
        print(
            "Incomplete exports lack manifest.json. If importing/creating with --apply, "
            "changes may be partial; check the printed output directory and Azure state. "
            "No automatic rollback was performed.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
