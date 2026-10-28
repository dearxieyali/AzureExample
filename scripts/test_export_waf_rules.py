import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import export_waf_rules as exporter


def sample_policy(name):
    return {
        "id": f"/subscriptions/test/resourceGroups/source/providers/{exporter.RESOURCE_TYPE}/{name}",
        "type": exporter.RESOURCE_TYPE,
        "name": name,
        "location": "chinanorth3",
        "tags": {"environment": "prod"},
        "etag": "read-only",
        "properties": {
            "provisioningState": "Succeeded",
            "resourceState": "Enabled",
            "applicationGateways": [{"id": "/source/gateway"}],
            "httpListeners": [{"id": "/source/listener"}],
            "pathBasedRules": [{"id": "/source/path"}],
            "applicationGatewayForContainers": [{"id": "/source/container-gateway"}],
            "policySettings": {
                "state": "Enabled", "mode": "Prevention",
                "requestBodyCheck": False,
                "logScrubbing": {"state": "Enabled", "scrubbingRules": []},
            },
            "customRules": [{
                "name": "regex", "priority": 1, "ruleType": "MatchRule",
                "state": "Enabled", "action": "Block",
                "matchConditions": [{
                    "matchVariables": [{"variableName": "RequestUri"}],
                    "operator": "Regex", "negationConditon": False,
                    "matchValues": ["[a-z]+", "[parameters('notAnExpression')]"],
                    "transforms": ["Lowercase"],
                }],
            }, {
                "name": "rate-limit", "priority": 2, "ruleType": "RateLimitRule",
                "rateLimitDuration": "OneMin", "rateLimitThreshold": 100,
                "groupByUserSession": [{"groupByVariables": [{"variableName": "ClientAddr"}]}],
                "matchConditions": [], "action": "Block", "state": "Disabled",
            }],
            "managedRules": {
                "managedRuleSets": [{
                    "ruleSetType": "OWASP", "ruleSetVersion": "3.2",
                    "computedDisabledRules": [{"ruleGroupName": "group", "rules": [942100]}],
                    "ruleGroupOverrides": [{
                        "ruleGroupName": "REQUEST-942-APPLICATION-ATTACK-SQLI",
                        "rules": [{"ruleId": "942100", "state": "Disabled", "action": "Log"}],
                    }],
                }],
                "exclusions": [{
                    "matchVariable": "RequestHeaderNames",
                    "selectorMatchOperator": "Equals", "selector": "X-Example",
                }],
                "exceptions": [{
                    "matchVariable": "RemoteAddr", "valueMatchOperator": "IPMatch",
                    "values": ["192.0.2.0/24"],
                }],
            },
            "tier": "Standard",
        },
    }


class ExportTests(unittest.TestCase):
    def test_migration_preserves_configuration_without_source_bindings(self):
        policy = sample_policy("test-policy")
        original = copy.deepcopy(policy)
        template, parameters = exporter.migration_documents(policy, "2024-05-01")
        actual = parameters["parameters"]["policyProperties"]["value"]
        expected = copy.deepcopy(original["properties"])
        for key in exporter.READ_ONLY_PROPERTIES:
            expected.pop(key, None)
        expected["managedRules"]["managedRuleSets"][0].pop("computedDisabledRules")
        self.assertEqual(actual, expected)
        self.assertEqual(policy, original)
        resource = template["resources"][0]
        self.assertEqual(resource["properties"], "[parameters('policyProperties')]")
        self.assertNotIn("id", resource)
        self.assertNotIn("etag", resource)
        self.assertEqual(
            actual["customRules"][0]["matchConditions"][0]["matchValues"][0], "[a-z]+"
        )

    def test_discovery_rejects_missing_or_ambiguous_names(self):
        resources = [sample_policy("policy"), sample_policy("POLICY")]
        with self.assertRaisesRegex(RuntimeError, "--resource-group"):
            exporter.find_policies(resources, ["policy"])
        with self.assertRaisesRegex(RuntimeError, "not found"):
            exporter.find_policies(resources, ["missing"])
        self.assertEqual(exporter.find_policies(resources[:1], ["POLICY"]), resources[:1])

    def test_selects_stable_api_and_rejects_unavailable_override(self):
        provider = {"resourceTypes": [{
            "resourceType": "applicationGatewayWebApplicationFirewallPolicies",
            "apiVersions": ["2025-01-01-preview", "2024-05-01", "2023-11-01"],
        }]}
        self.assertEqual(exporter.select_api_version(provider), "2024-05-01")
        with self.assertRaisesRegex(RuntimeError, "not advertised"):
            exporter.select_api_version(provider, "2026-01-01")

    def test_complete_export_uses_only_read_commands_and_refuses_overwrite(self):
        policies = [sample_policy(name) for name in exporter.DEFAULT_POLICIES]
        commands = []

        def fake_az(*arguments):
            commands.append(arguments)
            if arguments[:2] == ("cloud", "show"):
                return {
                    "name": "AzureChinaCloud",
                    "endpoints": {"resourceManager": "https://management.chinacloudapi.cn/"},
                }
            if arguments[:2] == ("account", "show"):
                return {"id": "test-subscription", "state": "Enabled"}
            if arguments[:2] == ("provider", "show"):
                return {"resourceTypes": [{
                    "resourceType": "ApplicationGatewayWebApplicationFirewallPolicies",
                    "apiVersions": ["2024-05-01"],
                }]}
            if arguments[:2] == ("resource", "list"):
                return policies
            if arguments[:3] == ("rest", "--method", "get"):
                url = arguments[arguments.index("--url") + 1]
                self.assertTrue(url.startswith("https://management.chinacloudapi.cn/"))
                for policy in policies:
                    if url.endswith(f"/{policy['name']}?api-version=2024-05-01"):
                        return policy
            self.fail(f"Unexpected Azure CLI call: {arguments}")

        with tempfile.TemporaryDirectory() as temporary:
            args = type("Args", (), {
                "subscription": exporter.DEFAULT_SUBSCRIPTION,
                "api_version": None, "resource_group": None,
                "policy_names": list(exporter.DEFAULT_POLICIES),
                "output_dir": Path(temporary) / "export",
            })()
            with patch.object(exporter.shutil, "which", return_value="/usr/bin/az"), \
                    patch.object(exporter, "az_json", side_effect=fake_az), \
                    patch("builtins.print"):
                output = exporter.export(args)
                manifest = json.loads((output / "manifest.json").read_text())
                self.assertEqual(len(manifest["policies"]), 2)
                for policy in policies:
                    directory = output / policy["name"]
                    self.assertEqual(
                        json.loads((directory / "raw.json").read_text()), policy
                    )
                    template = json.loads((directory / "template.json").read_text())
                    parameters = json.loads((directory / "parameters.json").read_text())
                    self.assertEqual(
                        json.loads((directory / "rules.json").read_text()),
                        exporter.rule_configuration(policy["properties"]),
                    )
                    self.assertEqual(
                        set(template["parameters"]), set(parameters["parameters"])
                    )
                with self.assertRaises(FileExistsError):
                    exporter.export(args)
        self.assertTrue(commands)

    def test_second_policy_failure_does_not_publish_partial_export(self):
        policies = [sample_policy(name) for name in exporter.DEFAULT_POLICIES]
        responses = [
            {
                "name": "AzureChinaCloud",
                "endpoints": {"resourceManager": "https://management.chinacloudapi.cn/"},
            },
            {"id": "test-subscription", "state": "Enabled"},
            {"resourceTypes": [{
                "resourceType": "ApplicationGatewayWebApplicationFirewallPolicies",
                "apiVersions": ["2024-05-01"],
            }]},
            policies,
            policies[0],
            RuntimeError("Forbidden"),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            args = type("Args", (), {
                "subscription": exporter.DEFAULT_SUBSCRIPTION,
                "api_version": None, "resource_group": None,
                "policy_names": list(exporter.DEFAULT_POLICIES),
                "output_dir": Path(temporary) / "export",
            })()
            with patch.object(exporter.shutil, "which", return_value="/usr/bin/az"), \
                    patch.object(exporter, "az_json", side_effect=responses):
                with self.assertRaisesRegex(RuntimeError, "Forbidden"):
                    exporter.export(args)
            self.assertFalse(args.output_dir.exists())

    def test_wrong_cloud_requires_explicit_login_without_changing_cloud(self):
        with patch.object(exporter.shutil, "which", return_value="/usr/bin/az"), \
                patch.object(exporter, "az_json", return_value={"name": "AzureCloud"}) as az:
            with self.assertRaisesRegex(RuntimeError, "az cloud set"):
                exporter.export(SimpleNamespace(
                    subscription="test-subscription", api_version=None,
                ))
            az.assert_called_once_with("cloud", "show")


class ImportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        self.source.mkdir()
        self.args = SimpleNamespace(
            import_dir=self.source, subscription="target-subscription",
            api_version=None, resource_group="target-group",
            policy_names=list(exporter.DEFAULT_POLICIES),
            policy_map=None,
            backup_dir=self.root / "backup", apply=False, timeout=30,
        )
        self.targets = {}
        self.commands = []
        self.fail_put_number = None
        self.put_count = 0
        self.change_etag_before_apply = False
        self.read_count = 0
        self.final_state = "Succeeded"
        for name in exporter.DEFAULT_POLICIES:
            policy = sample_policy(name)
            directory = self.source / name
            directory.mkdir()
            exporter.write_json(directory / "rules.json", exporter.rule_configuration(
                policy["properties"],
            ))
            target = copy.deepcopy(policy)
            target["id"] = target["id"].replace(
                "/subscriptions/test/resourceGroups/source/",
                "/subscriptions/target-subscription/resourceGroups/target-group/",
            )
            target["etag"] = "target-etag"
            target["location"] = "chinaeast2"
            target["tags"] = {"environment": "target"}
            target["properties"]["policySettings"]["mode"] = "Detection"
            target["properties"]["customRules"] = [{
                "name": "target-only", "priority": 50,
                "action": "Allow", "ruleType": "MatchRule",
            }]
            target["properties"]["applicationGateways"] = [{"id": "/target/gateway"}]
            self.targets[name] = target
        exporter.write_json(self.source / "manifest.json", {
            "subscriptionId": exporter.DEFAULT_SUBSCRIPTION,
            "apiVersion": "2024-05-01",
            "policies": [{"name": name} for name in exporter.DEFAULT_POLICIES],
        })

    def fake_az(self, *arguments):
        self.commands.append(arguments)
        if arguments[:2] == ("cloud", "show"):
            return {
                "name": "AzureChinaCloud",
                "endpoints": {"resourceManager": "https://management.chinacloudapi.cn/"},
            }
        if arguments[:2] == ("account", "show"):
            return {"id": self.args.subscription, "state": "Enabled"}
        if arguments[:2] == ("provider", "show"):
            return {"resourceTypes": [{
                "resourceType": "ApplicationGatewayWebApplicationFirewallPolicies",
                "apiVersions": ["2024-05-01"],
            }]}
        if arguments[:2] == ("resource", "list"):
            return list(copy.deepcopy(self.targets).values())
        if arguments[0] == "rest":
            url = arguments[arguments.index("--url") + 1]
            name = url.split("?")[0].rsplit("/", 1)[1]
            method = arguments[arguments.index("--method") + 1]
            target = self.targets[name]
            if method == "get":
                self.read_count += 1
                result = copy.deepcopy(target)
                if self.change_etag_before_apply and self.read_count > 2:
                    result["etag"] = "concurrent-change"
                return result
            if method == "put":
                self.put_count += 1
                if self.put_count == self.fail_put_number:
                    raise RuntimeError("Simulated target rejection")
                body_file = arguments[arguments.index("--body") + 1]
                body = json.loads(Path(body_file[1:]).read_text())
                original_properties = target["properties"]
                target.update(body)
                for key in exporter.READ_ONLY_PROPERTIES:
                    if key in original_properties:
                        target["properties"][key] = original_properties[key]
                target["properties"]["provisioningState"] = self.final_state
                target["etag"] = "updated-etag"
                return copy.deepcopy(target)
        self.fail(f"Unexpected command: {arguments}")

    def run_import(self):
        with patch.object(exporter.shutil, "which", return_value="/usr/bin/az"), \
                patch.object(exporter, "az_json", side_effect=self.fake_az), \
                patch("builtins.print"):
            return exporter.import_rules(self.args)

    def test_preview_backs_up_targets_without_writing_azure(self):
        originals = copy.deepcopy(self.targets)
        output = self.run_import()
        self.assertEqual(self.put_count, 0)
        self.assertEqual(self.targets, originals)
        for name in exporter.DEFAULT_POLICIES:
            self.assertEqual(
                json.loads((output / name / "before.json").read_text()), originals[name],
            )
            body = json.loads((output / name / "request.json").read_text())
            self.assertEqual(body["location"], originals[name]["location"])
            self.assertEqual(body["tags"], originals[name]["tags"])
            self.assertEqual(
                body["properties"]["policySettings"],
                originals[name]["properties"]["policySettings"],
            )
            self.assertNotIn("applicationGateways", body["properties"])
            self.assertFalse((output / name / "after.json").exists())

    def test_apply_replaces_all_rules_and_preserves_target_configuration(self):
        originals = copy.deepcopy(self.targets)
        self.args.apply = True
        output = self.run_import()
        self.assertEqual(self.put_count, 2)
        for name, target in self.targets.items():
            rules = exporter.rule_configuration(target["properties"])
            self.assertEqual(rules, exporter.load_rules(self.source, name))
            self.assertEqual(target["properties"]["policySettings"],
                             originals[name]["properties"]["policySettings"])
            self.assertEqual(target["properties"]["tier"],
                             originals[name]["properties"]["tier"])
            self.assertEqual(target["properties"]["applicationGateways"],
                             originals[name]["properties"]["applicationGateways"])
            self.assertEqual(target["tags"], originals[name]["tags"])
            self.assertEqual(target["location"], originals[name]["location"])
            self.assertTrue((output / name / "after.json").exists())
        writes = [command for command in self.commands if command[:3] == ("rest", "--method", "put")]
        self.assertTrue(all("/subscriptions/target-subscription/" in command[
            command.index("--url") + 1
        ] for command in writes))

    def test_different_name_mapping_previews_and_updates_correct_targets(self):
        first, second = exporter.DEFAULT_POLICIES
        renamed = {}
        for source, destination in ((first, "qa-main"), (second, "qa-portal")):
            target = self.targets[source]
            target["name"] = destination
            target["id"] = target["id"].rsplit("/", 1)[0] + "/" + destination
            renamed[destination] = target
            path = self.source / source / "rules.json"
            rules = json.loads(path.read_text())
            rules["customRules"][0]["name"] = source + "-rule"
            path.unlink()
            exporter.write_json(path, rules)
        self.targets = renamed
        originals = copy.deepcopy(renamed)
        self.args.policy_map = [(second.upper(), "qa-portal"), (first, "qa-main")]
        preview = self.run_import()
        self.assertEqual(self.put_count, 0)
        self.assertEqual(self.targets, originals)
        plan = json.loads((preview / "plan.json").read_text())
        self.assertEqual(
            [(item["sourcePolicyName"], item["targetPolicyName"])
             for item in plan["policyMappings"]],
            [(second, "qa-portal"), (first, "qa-main")],
        )
        self.assertEqual(
            json.loads((preview / first / "before.json").read_text())["name"], "qa-main",
        )
        self.args.backup_dir = self.root / "applied"
        self.args.apply = True
        output = self.run_import()
        self.assertEqual(self.put_count, 2)
        for source, destination in ((first, "qa-main"), (second, "qa-portal")):
            target = self.targets[destination]
            self.assertEqual(
                exporter.rule_configuration(target["properties"]),
                exporter.load_rules(self.source, source),
            )
            self.assertEqual(target["name"], destination)
            self.assertEqual(target["location"], originals[destination]["location"])
            self.assertEqual(target["tags"], originals[destination]["tags"])
            self.assertEqual(target["properties"]["policySettings"],
                             originals[destination]["properties"]["policySettings"])
            self.assertEqual(target["properties"]["applicationGateways"],
                             originals[destination]["properties"]["applicationGateways"])
            self.assertTrue((output / source / "after.json").exists())

    def test_mapping_imports_only_selected_pair(self):
        first, second = exporter.DEFAULT_POLICIES
        self.args.policy_map = [(first, first)]
        self.targets.pop(second)
        self.args.apply = True
        output = self.run_import()
        self.assertEqual(self.put_count, 1)
        self.assertTrue((output / first / "after.json").exists())
        self.assertFalse((output / second).exists())

    def test_mapping_rejects_duplicate_sources_or_targets_before_azure_calls(self):
        first, second = exporter.DEFAULT_POLICIES
        for mappings in (
            [(first, "qa"), (first.upper(), "qa-portal")],
            [(first, "qa"), (second, "QA")],
        ):
            self.args.policy_map = mappings
            with self.assertRaisesRegex(RuntimeError, "Duplicate"):
                self.run_import()
            self.assertFalse(self.commands)

    def test_mapping_requires_existing_target(self):
        first = exporter.DEFAULT_POLICIES[0]
        self.args.policy_map = [(first, "missing-target")]
        self.args.apply = True
        with self.assertRaisesRegex(RuntimeError, "Policy not found: missing-target"):
            self.run_import()
        self.assertEqual(self.put_count, 0)
        self.assertFalse(self.args.backup_dir.exists())

    def test_mapping_cli_accepts_pairs_and_rejects_ambiguous_or_malformed_input(self):
        first = exporter.DEFAULT_POLICIES[0]
        arguments = [
            "--import-dir", "export", "--subscription", "target",
            "--policy-map", f"{first}=qa",
        ]
        with patch("sys.argv", ["export_waf_rules.py", *arguments]):
            self.assertEqual(exporter.parse_args().policy_map, [(first, "qa")])
        for invalid in (
            [*arguments, "--policy-names", first],
            ["--policy-map", f"{first}=qa"],
            [*arguments[:-1], "no-equals-sign"],
            [*arguments[:-1], f"{first}="],
            [*arguments[:-1], "=qa"],
            [*arguments[:-1], f"{first}=qa=extra"],
        ):
            with patch("sys.argv", ["export_waf_rules.py", *invalid]), \
                    patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                exporter.parse_args()
            self.assertEqual(error.exception.code, 2)

    def test_missing_target_stops_before_any_update(self):
        self.args.apply = True
        self.targets.pop(exporter.DEFAULT_POLICIES[1])
        with self.assertRaisesRegex(RuntimeError, "not found"):
            self.run_import()
        self.assertEqual(self.put_count, 0)
        self.assertFalse(self.args.backup_dir.exists())

    def test_absent_optional_source_rules_clear_target_exclusions_and_overrides(self):
        self.args.apply = True
        for name in exporter.DEFAULT_POLICIES:
            path = self.source / name / "rules.json"
            rules = json.loads(path.read_text())
            rules["managedRules"].pop("exclusions")
            rules["managedRules"].pop("exceptions")
            rules["managedRules"]["managedRuleSets"][0].pop("ruleGroupOverrides")
            path.unlink()
            exporter.write_json(path, rules)
        self.run_import()
        for target in self.targets.values():
            managed = target["properties"]["managedRules"]
            self.assertEqual(managed["exclusions"], [])
            self.assertEqual(managed["exceptions"], [])
            self.assertEqual(managed["managedRuleSets"][0]["ruleGroupOverrides"], [])

    def test_changed_target_aborts_before_update(self):
        self.args.apply = True
        self.change_etag_before_apply = True
        with self.assertRaisesRegex(RuntimeError, "changed after backup"):
            self.run_import()
        self.assertEqual(self.put_count, 0)
        self.assertTrue((self.args.backup_dir / "plan.json").exists())

    def test_second_failure_keeps_backups_and_first_verified_receipt(self):
        self.args.apply = True
        self.fail_put_number = 2
        with self.assertRaisesRegex(RuntimeError, "Simulated target rejection"):
            self.run_import()
        first, second = exporter.DEFAULT_POLICIES
        self.assertTrue((self.args.backup_dir / first / "after.json").exists())
        self.assertFalse((self.args.backup_dir / second / "after.json").exists())
        self.assertTrue((self.args.backup_dir / second / "before.json").exists())

    def test_failed_or_timed_out_update_does_not_report_success_or_continue(self):
        self.args.apply = True
        for state, message in (("Failed", "update failed"), ("Updating", "Timed out")):
            self.final_state = state
            self.args.backup_dir = self.root / state
            self.put_count = 0
            for target in self.targets.values():
                target["properties"]["provisioningState"] = "Succeeded"
            with patch.object(exporter.time, "monotonic", side_effect=[0, 31]):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.run_import()
            self.assertEqual(self.put_count, 1)
            self.assertFalse(any(self.args.backup_dir.glob("*/after.json")))

    def test_rejects_source_subscription_as_target(self):
        self.args.subscription = exporter.DEFAULT_SUBSCRIPTION
        self.args.apply = True
        with self.assertRaisesRegex(RuntimeError, "differ from"):
            self.run_import()
        self.assertEqual(self.put_count, 0)

    def test_older_export_parameter_files_are_supported(self):
        name = exporter.DEFAULT_POLICIES[0]
        path = self.source / name
        (path / "rules.json").unlink()
        _, parameters = exporter.migration_documents(sample_policy(name), "2024-05-01")
        exporter.write_json(path / "parameters.json", parameters)
        self.assertEqual(exporter.load_rules(self.source, name),
                         exporter.rule_configuration(sample_policy(name)["properties"]))

    def test_verification_detects_setting_binding_and_rule_changes(self):
        before = sample_policy("policy")
        rules = exporter.rule_configuration(before["properties"])
        body = {
            "location": before["location"],
            "tags": before["tags"],
            "properties": exporter.writable_properties(before),
        }
        for mutation in ("settings", "bindings", "rules", "exclusions"):
            after = copy.deepcopy(before)
            if mutation == "settings":
                after["properties"]["policySettings"]["mode"] = "Detection"
            elif mutation == "bindings":
                after["properties"]["applicationGateways"] = []
            elif mutation == "rules":
                after["properties"]["customRules"].append({"name": "unexpected"})
            else:
                body_without_exclusions = copy.deepcopy(body)
                body_without_exclusions["properties"]["managedRules"].pop("exclusions")
                rules_without_exclusions = copy.deepcopy(rules)
                rules_without_exclusions["managedRules"].pop("exclusions")
                with self.assertRaisesRegex(RuntimeError, "Verification failed"):
                    exporter.verify_import(
                        before, after, body_without_exclusions, rules_without_exclusions,
                    )
                continue
            with self.assertRaisesRegex(RuntimeError, "Verification failed"):
                exporter.verify_import(before, after, body, rules)

    def test_import_requires_explicit_target_and_apply_requires_import(self):
        for arguments in (["--import-dir", "export"], ["--apply"]):
            with patch("sys.argv", ["export_waf_rules.py", *arguments]), \
                    patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                exporter.parse_args()
            self.assertEqual(error.exception.code, 2)


class CreateTests(unittest.TestCase):
    def setUp(self):
        ImportTests.setUp(self)
        self.args.output_dir = self.root / "creation"
        self.args.location = None
        self.existing = copy.deepcopy(self.targets)
        self.targets = {}
        self.appear_on_recheck = False
        self.list_count = 0
        self.corrupt_result = False
        for name in exporter.DEFAULT_POLICIES:
            _, parameters = exporter.migration_documents(sample_policy(name), "2024-05-01")
            exporter.write_json(self.source / name / "parameters.json", parameters)

    def fake_az(self, *arguments):
        if arguments[:2] == ("group", "show"):
            self.commands.append(arguments)
            return {
                "name": "target-group",
                "id": "/subscriptions/target-subscription/resourceGroups/target-group",
            }
        if arguments[:2] == ("resource", "list"):
            self.list_count += 1
            if self.appear_on_recheck and self.list_count > 1:
                self.targets.update(copy.deepcopy(self.existing))
        if arguments[:3] == ("rest", "--method", "put"):
            self.commands.append(arguments)
            self.put_count += 1
            self.assertIn("If-None-Match=*", arguments)
            if self.put_count == self.fail_put_number:
                raise RuntimeError("Simulated creation rejection")
            url = arguments[arguments.index("--url") + 1]
            resource_id = url.split("?", 1)[0].split(".cn", 1)[1]
            name = resource_id.rsplit("/", 1)[1]
            self.assertNotIn(name, self.targets)
            request = arguments[arguments.index("--body") + 1]
            body = json.loads(Path(request[1:]).read_text())
            target = {
                **body, "id": resource_id, "name": name, "type": exporter.RESOURCE_TYPE,
                "etag": "created",
            }
            target["properties"]["provisioningState"] = self.final_state
            if self.corrupt_result:
                target["properties"]["customRules"] = []
            self.targets[name] = target
            return copy.deepcopy(target)
        return ImportTests.fake_az(self, *arguments)

    def run_create(self):
        with patch.object(exporter.shutil, "which", return_value="/usr/bin/az"), \
                patch.object(exporter, "az_json", side_effect=self.fake_az), \
                patch("builtins.print"):
            return exporter.create_policies(self.args)

    def test_preview_includes_all_rules_settings_tags_without_bindings(self):
        output = self.run_create()
        self.assertEqual(self.put_count, 0)
        self.assertFalse(self.targets)
        for name in exporter.DEFAULT_POLICIES:
            request = json.loads((output / name / "request.json").read_text())
            source = sample_policy(name)
            expected = exporter.writable_properties(source)
            expected.update(exporter.rule_configuration(source["properties"]))
            self.assertEqual(request, {
                "location": source["location"], "tags": source["tags"], "properties": expected,
            })
            self.assertFalse((output / name / "after.json").exists())

    def test_apply_creates_same_names_with_all_rules_settings_and_region_override(self):
        self.args.apply = True
        self.args.location = "chinaeast2"
        output = self.run_create()
        self.assertEqual(self.put_count, 2)
        for name, target in self.targets.items():
            source = sample_policy(name)
            self.assertEqual(target["name"], name)
            self.assertEqual(target["location"], "chinaeast2")
            self.assertEqual(target["tags"], source["tags"])
            self.assertEqual(target["properties"]["policySettings"],
                             source["properties"]["policySettings"])
            self.assertEqual(target["properties"]["tier"], source["properties"]["tier"])
            self.assertEqual(exporter.rule_configuration(target["properties"]),
                             exporter.load_rules(self.source, name))
            self.assertNotIn("applicationGateways", target["properties"])
            self.assertTrue((output / name / "after.json").exists())

    def test_existing_policy_is_skipped_without_importing_rules(self):
        first, second = exporter.DEFAULT_POLICIES
        # Azure names are case-insensitive.
        original = copy.deepcopy(self.existing[first])
        original["name"] = first.upper()
        self.targets[first] = copy.deepcopy(original)
        self.args.apply = True
        output = self.run_create()
        self.assertEqual(self.put_count, 1)
        self.assertEqual(self.targets[first], original)
        self.assertFalse((output / first).exists())
        self.assertTrue((output / second / "after.json").exists())
        plan = json.loads((output / "plan.json").read_text())
        self.assertEqual(plan["policies"][0]["action"], "skip-existing")

    def test_all_existing_policies_result_in_no_writes(self):
        self.targets = copy.deepcopy(self.existing)
        self.args.apply = True
        output = self.run_create()
        self.assertEqual(self.put_count, 0)
        self.assertEqual(self.targets, self.existing)
        self.assertTrue((output / "plan.json").exists())

    def test_policy_appearing_before_put_is_skipped(self):
        self.args.apply = True
        self.appear_on_recheck = True
        output = self.run_create()
        self.assertEqual(self.put_count, 0)
        self.assertEqual(self.targets, self.existing)
        for name in exporter.DEFAULT_POLICIES:
            self.assertTrue((output / name / "skipped.json").exists())
            self.assertFalse((output / name / "after.json").exists())

    def test_second_creation_failure_preserves_first_result(self):
        self.args.apply = True
        self.fail_put_number = 2
        with self.assertRaisesRegex(RuntimeError, "creation rejection"):
            self.run_create()
        first, second = exporter.DEFAULT_POLICIES
        self.assertTrue((self.args.output_dir / first / "after.json").exists())
        self.assertFalse((self.args.output_dir / second / "after.json").exists())
        self.assertNotIn(second, self.targets)

    def test_verification_failure_is_not_reported_as_success(self):
        self.args.apply = True
        self.corrupt_result = True
        with self.assertRaisesRegex(RuntimeError, "Verification failed"):
            self.run_create()
        self.assertEqual(self.put_count, 1)
        self.assertFalse(any(self.args.output_dir.glob("*/after.json")))

    def test_failed_or_timed_out_creation_stops_without_verified_receipt(self):
        self.args.apply = True
        for state, message in (("Failed", "update failed"), ("Updating", "Timed out")):
            self.targets = {}
            self.put_count = 0
            self.final_state = state
            self.args.output_dir = self.root / state
            with patch.object(exporter.time, "monotonic", side_effect=[0, 31]):
                with self.assertRaisesRegex(RuntimeError, message):
                    self.run_create()
            self.assertEqual(self.put_count, 1)
            self.assertFalse(any(self.args.output_dir.glob("*/after.json")))

    def test_selected_policy_and_legacy_export_are_supported(self):
        name = exporter.DEFAULT_POLICIES[1]
        self.args.policy_names = [name]
        self.args.apply = True
        (self.source / name / "rules.json").unlink()
        output = self.run_create()
        self.assertEqual(set(self.targets), {name})
        self.assertEqual(self.put_count, 1)
        self.assertTrue((output / name / "after.json").exists())

    def test_missing_source_configuration_prevents_all_writes(self):
        name = exporter.DEFAULT_POLICIES[1]
        (self.source / name / "parameters.json").unlink()
        self.args.apply = True
        with self.assertRaises(FileNotFoundError):
            self.run_create()
        self.assertFalse(self.commands)
        self.assertEqual(self.put_count, 0)

    def test_create_subcommand_requires_explicit_target_and_input(self):
        arguments = [
            "create", "--import-dir", "export", "--subscription", "target",
            "--resource-group", "target-group", "--location", "chinaeast2", "--apply",
        ]
        with patch("sys.argv", ["export_waf_rules.py", *arguments]):
            args = exporter.parse_args()
        self.assertEqual(args.command, "create")
        self.assertEqual(args.location, "chinaeast2")
        self.assertTrue(args.apply)
        for missing in ("--import-dir", "--subscription", "--resource-group"):
            invalid = arguments.copy()
            index = invalid.index(missing)
            del invalid[index:index + 2]
            with patch("sys.argv", ["export_waf_rules.py", *invalid]), \
                    patch("sys.stderr"), self.assertRaises(SystemExit) as error:
                exporter.parse_args()
            self.assertEqual(error.exception.code, 2)

    def test_main_dispatches_create_without_affecting_legacy_export(self):
        for arguments, function in (
            ([], "export"),
            ([
                "create", "--import-dir", "export", "--subscription", "target",
                "--resource-group", "target-group",
            ], "create_policies"),
        ):
            with patch("sys.argv", ["export_waf_rules.py", *arguments]), \
                    patch.object(exporter.os, "umask"), \
                    patch.object(exporter, function) as operation:
                self.assertEqual(exporter.main(), 0)
                operation.assert_called_once()


if __name__ == "__main__":
    unittest.main()
