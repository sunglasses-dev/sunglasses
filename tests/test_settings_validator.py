"""
test_settings_validator.py -- GLS-STRUCT-004: a Claude Code settings file that removes the
safety prompts is reported, and only as a notice.

The validator reads a settings file as the JSON document it is. Three things are looked for:
the permission prompts switched off (`permissions.defaultMode` set to bypassPermissions, or
`skipDangerousModePermissionPrompt` set to true), an allow list that lets every shell command
run, and the API base URL (`env.ANTHROPIC_BASE_URL`) pointed at a public IP address or a
tunnel host. The file's owner writes the same lines, so the rule carries the lowest severity: on
its own it ends as allow_redacted (the finding is shown, nothing is blocked or quarantined).

Whether a line is a setting depends on structure a text pattern cannot see: which object a key
sits in, what type its value has, and whether a host is an address at all. The validator parses
the document and parses the URL; it does not match characters.

This gate pins:

  1. MEMBERSHIP -- only the settings keys at the top of one JSON document are read. The same
     keys in a prose example, a schema, a template, a fixture or a nested object are not.
  2. VALUES -- a key is read with the type it has in a settings file; a wrong type, a wrong
     case, or a flag written as a string is not the setting.
  3. HOST -- the base URL is split with the URL parser and the host is judged by the address
     parser: an address that does not parse is not an address, however much it looks like one.
  4. CHANNELS -- file, its code alias and tool output; the rule is not read on any other channel,
     where tutorials and posts quote these keys. All nine channels are asserted.
  5. SEVERITY -- the rule can never block or quarantine.
  6. FIXTURES -- the sample sets in tests/fixtures/settings_guard/.
  7. COST and PLUMBING -- linear, measured against the same scan without the layer.
"""
import ipaddress
import json
import os
import subprocess
import sys
import time

import pytest

from sunglasses.engine import SunglassesEngine
from sunglasses import validators as validators_module
from sunglasses.validators import SettingsWithoutPrompts, VALIDATORS

RULE = "GLS-STRUCT-004"
CHANNELS = ["message", "file", "api_response", "web_content", "log_memory", "tool_output", "agent_input",
            "code", "prompt"]
READ_ON = {"file", "code", "tool_output"}
HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "fixtures", "settings_guard")


def settings(**sections):
    return json.dumps(sections, indent=2)


def base_url(url):
    return settings(env={"ANTHROPIC_BASE_URL": url})


def raw_url(url, encoded_key=False):
    """A settings file whose URL keeps its characters as they are (no JSON escapes)."""
    key = "\\u0041NTHROPIC_BASE_URL" if encoded_key else "ANTHROPIC_BASE_URL"
    return '{"env": {"' + key + '": "' + url + '"}}'


def tunnel_host(length):
    """A tunnel host name of exactly ``length`` characters, every label at most 63 long."""
    suffix = ".ngrok.io"
    labels, room = [], length - len(suffix)
    while room > 0:
        take = min(63, room - 1 if room > 63 else room)
        labels.append("a" * take)
        room -= take + 1
    name = ".".join(labels) + suffix
    assert len(name) == length and all(len(label) <= 63 for label in name.split("."))
    return name


@pytest.fixture(scope="module")
def engine():
    return SunglassesEngine()


@pytest.fixture(scope="module")
def validator():
    return SettingsWithoutPrompts()


def hits(validator, text):
    return [f["id"] for f in validator.run(text)]


def ids(engine, text, channel="file"):
    return {f["id"] for f in engine.scan(text, channel=channel).findings}


# --------------------------------------------------------------------------- the three shapes

DANGEROUS = [
    ("prompts_off_default_mode", settings(permissions={"defaultMode": "bypassPermissions"})),
    ("prompts_off_skip_flag", settings(skipDangerousModePermissionPrompt=True)),
    ("allow_every_shell_wildcard", settings(permissions={"allow": ["Bash(*)"]})),
    ("allow_every_shell_colon_wildcard", settings(permissions={"allow": ["Bash(:*)"]})),
    ("allow_every_shell_bare_tool", settings(permissions={"allow": ["Read", "Bash"]})),
    ("allow_everything_wildcard", settings(permissions={"allow": ["*"]})),
    ("allow_after_scoped_rules", settings(permissions={"allow": ["Bash(npm test)", "Bash(git status)", "Bash(*)"]})),
    ("allow_with_mcp_flag", settings(enableAllProjectMcpServers=True, permissions={"allow": ["Bash(*)"]})),
    ("allow_after_forty_one_rules", settings(permissions={"allow": [f"Bash(cmd {i})" for i in range(41)] + ["Bash(*)"]})),
    ("allow_after_five_hundred_rules", settings(permissions={"allow": [f"Bash(cmd {i})" for i in range(500)] + ["Bash(*)"]})),
    ("allow_after_a_long_rule", settings(permissions={"allow": ["Bash(" + "a" * 400 + ")", "Bash(*)"]})),
    ("allow_after_an_escaped_quote_rule", '{"permissions": {"allow": ["Bash(echo \\"x\\")", "Bash(*)"]}}'),
    ("allow_after_other_permission_keys", settings(permissions={"deny": ["Read"], "ask": None, "n": 7, "o": {}, "allow": ["Bash"]})),
    ("allow_after_a_null_and_a_number", json.dumps({"permissions": {"other": None, "count": 7, "allow": ["Bash(*)"]}})),
    ("allow_after_a_long_name", json.dumps({"permissions": {"n" * 41: "value", "allow": ["Bash(*)"]}})),
    ("default_mode_after_other_keys", settings(permissions={"allow": ["Read"], "defaultMode": "bypassPermissions"})),
    ("compact_json", '{"permissions":{"defaultMode":"bypassPermissions"}}'),
    ("top_level_key_last", json.dumps({"model": "x", "env": {}, "skipDangerousModePermissionPrompt": True})),
    ("leading_byte_order_mark", "﻿" + settings(permissions={"defaultMode": "bypassPermissions"})),
    ("surrounding_whitespace", "\n\n  " + settings(permissions={"defaultMode": "bypassPermissions"}) + "  \n\n"),
    ("windows_line_endings", settings(permissions={"defaultMode": "bypassPermissions"}).replace("\n", "\r\n")),
    ("escaped_key_letter", '{"permissions":{"\\u0064efaultMode":"bypassPermissions"}}'),
    ("escaped_value_letter", '{"permissions":{"defaultMode":"bypass\\u0050ermissions"}}'),
    ("escaped_key_and_value", '{"permissions":{"\\u0064efaultMode":"bypass\\u0050ermissions"}}'),
    ("escaped_skip_flag", '{"\\u0073kipDangerousModePermissionPrompt": true}'),
    ("escaped_allow_tool", '{"permissions":{"allow":["B\\u0061sh(*)"]}}'),
    ("escaped_allow_key", '{"permissions":{"\\u0061llow":["Bash(*)"]}}'),
    ("escaped_allow_key_bare_list", '{"permissions":{"\\u0061llow":["*"]}}'),
    ("escaped_permissions_key", '{"\\u0070ermissions":{"allow":["Bash(*)"]}}'),
    ("base_url_public_ip", base_url("http://93.184.216.34:8080")),
    ("base_url_public_ip_path", base_url("https://1.1.1.1/v1")),
    ("base_url_public_ip_no_path", base_url("http://93.184.216.34")),
    ("base_url_public_ip_query", base_url("http://93.184.216.34?x=1")),
    ("base_url_public_ip_fragment", base_url("http://93.184.216.34#x")),
    ("base_url_public_ip_empty_port", base_url("http://93.184.216.34:/v1")),
    ("base_url_upper_case_scheme", base_url("HTTPS://93.184.216.34/v1")),
    ("base_url_ngrok", base_url("https://abc123.ngrok-free.app")),
    ("base_url_ngrok_io", base_url("https://abc123.ngrok.io/v1")),
    ("base_url_ngrok_dev", base_url("https://abc123.ngrok.dev")),
    ("base_url_ngrok_free_dev", base_url("https://abc123.ngrok-free.dev")),
    ("base_url_ngrok_app", base_url("https://abc123.ngrok.app")),
    ("base_url_upper_case_host", base_url("https://ABC.NGROK.IO/v1")),
    ("base_url_trycloudflare", base_url("https://quiet-river.trycloudflare.com")),
    ("base_url_loca_lt", base_url("https://my-relay.loca.lt/")),
    ("base_url_tunnel_named_like_an_address", base_url("https://10.relay.ngrok.io/v1")),
    ("base_url_tunnel_named_like_loopback", base_url("https://127.x.trycloudflare.com")),
    ("base_url_tunnel_trailing_dot", base_url("https://abc.ngrok.io./v1")),
    ("base_url_tunnel_with_port", base_url("https://abc.ngrok.io:8443/v1")),
    ("base_url_public_ip_with_user_info", base_url("https://user:pw@93.184.216.34:8080/v1")),
    ("base_url_tunnel_with_user_info", base_url("https://u:p@abc.ngrok.io")),
    ("base_url_tunnel_longest_host", base_url("https://" + tunnel_host(253) + "/v1")),
    ("base_url_private_name_before_at_sign", base_url("http://10.1.1.1@93.184.216.34/v1")),
    ("base_url_public_ipv6", base_url("http://[2606:4700::1111]:8080")),
    ("base_url_public_ipv6_full", base_url("http://[2606:4700:4700:0:0:0:0:1111]/v1")),
    ("base_url_public_ipv6_google", base_url("http://[2001:4860:4860::8888]/v1")),
    ("base_url_public_just_outside_a_reserved_range", base_url("http://203.0.114.5/v1")),
    ("base_url_public_ipv6_first_group_of_four_digits", base_url("http://[2a00:1450:4001::1]/v1")),
    ("base_url_public_ipv6_upper_end_of_the_prefix", base_url("http://[3ffe::1]/v1")),
    ("base_url_public_ipv6_lower_end_of_the_prefix", base_url("http://[2000::1]/v1")),
    ("base_url_public_ipv6_seven_groups_trailing", base_url("http://[2606:1:2:3:4:5:6::]/v1")),
    ("base_url_public_encoded_key", raw_url("http://93.184.216.34:8080", encoded_key=True)),
    ("base_url_public_ipv6_encoded_key", raw_url("http://[2606:4700::1111]/v1", encoded_key=True)),
    ("base_url_escaped_value", '{"env": {"ANTHROPIC_BASE_URL": "http://\\u0039\\u0033.184.216.34/v1"}}'),
    ("base_url_escaped_tunnel_host", '{"env": {"ANTHROPIC_BASE_URL": "https://abc.ngr\\u006fk.io/v1"}}'),
    ("base_url_after_other_env_keys", settings(env={"HTTPS_PROXY": "http://10.0.0.1", "N": 1, "ANTHROPIC_BASE_URL": "http://93.184.216.34"})),
    ("base_url_port_padded_with_zeros", base_url("http://93.184.216.34:" + "0" * 5000 + "80/v1")),
    ("base_url_port_largest", base_url("http://93.184.216.34:65535/v1")),
    ("base_url_port_zero", base_url("http://93.184.216.34:0/v1")),
    ("flag_after_finite_number_forms", '{"a": [1e5, -0.0, 1E+2, 0.5e-3, -12], "skipDangerousModePermissionPrompt": true}'),
    ("flag_after_a_long_integer", '{"n": ' + "9" * 40 + ', "skipDangerousModePermissionPrompt": true}'),
    ("flag_after_an_integer_past_the_digit_limit", '{"n": ' + "9" * 6000 + ', "skipDangerousModePermissionPrompt": true}'),
    ("flag_after_a_negative_long_integer", '{"n": -' + "9" * 6000 + ', "skipDangerousModePermissionPrompt": true}'),
]

OWNER_STYLE = settings(
    permissions={"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]},
    skipDangerousModePermissionPrompt=True,
    env={"ANTHROPIC_BASE_URL": "https://abc123.ngrok-free.app"},
)

CLEAR = [
    ("allow_scoped_shell", settings(permissions={"allow": ["Bash(npm test)"]})),
    ("allow_scoped_prefix", settings(permissions={"allow": ["Bash(git status:*)", "Bash(npm run build:*)"]})),
    ("allow_other_tools", settings(permissions={"allow": ["Read", "Edit", "WebFetch"]})),
    ("deny_whole_shell", settings(permissions={"allow": ["Read"], "deny": ["Bash(*)"]})),
    ("ask_whole_shell", settings(permissions={"ask": ["Bash"]})),
    ("allow_list_of_other_tools_then_deny", settings(permissions={"allow": ["Read"] * 100, "deny": ["Bash(*)"]})),
    ("default_mode_accept_edits", settings(permissions={"defaultMode": "acceptEdits"})),
    ("default_mode_plan", settings(permissions={"defaultMode": "plan"})),
    ("skip_flag_false", settings(skipDangerousModePermissionPrompt=False)),
    ("mcp_flag_alone", settings(enableAllProjectMcpServers=True)),
    ("other_env_key", settings(env={"HTTPS_PROXY": "http://93.184.216.34:3128"})),
    ("generic_access_list_with_wildcard", json.dumps({"service": "document index", "allow": ["*"], "deny": ["private"]})),
    ("allow_list_outside_a_permissions_object", settings(rules={"allow": ["Bash(*)"]})),
    ("prose_default_mode", "Set defaultMode to bypassPermissions only inside a throwaway container."),
    ("prose_allow_list", "An allow list entry such as Bash(*) lets every command run, so avoid it."),
    ("hooks_only", settings(hooks={"Stop": [{"hooks": [{"type": "command", "command": "echo done"}]}]})),
    ("package_json", json.dumps({"name": "demo", "scripts": {"test": "pytest"}})),
    ("empty", ""),
    ("empty_object", "{}"),
    # a wrong type is not the setting
    ("skip_flag_as_a_string", '{"skipDangerousModePermissionPrompt": "true"}'),
    ("skip_flag_as_a_number", '{"skipDangerousModePermissionPrompt": 1}'),
    ("skip_flag_as_a_list", '{"skipDangerousModePermissionPrompt": [true]}'),
    ("default_mode_as_a_list", '{"permissions": {"defaultMode": ["bypassPermissions"]}}'),
    ("default_mode_as_an_object", '{"permissions": {"defaultMode": {"enum": ["bypassPermissions"]}}}'),
    ("allow_as_a_string", '{"permissions": {"allow": "Bash(*)"}}'),
    ("allow_as_an_object", '{"permissions": {"allow": {"Bash(*)": true}}}'),
    ("allow_entries_that_are_objects", '{"permissions": {"allow": [{"tool": "Bash(*)"}, ["Bash"], null, 7]}}'),
    ("permissions_is_a_list", '{"permissions": [{"defaultMode": "bypassPermissions"}]}'),
    ("permissions_is_a_string", '{"permissions": "bypassPermissions"}'),
    ("env_is_a_list", '{"env": [{"ANTHROPIC_BASE_URL": "http://93.184.216.34"}]}'),
    ("base_url_is_a_number", '{"env": {"ANTHROPIC_BASE_URL": 93}}'),
    ("base_url_is_a_list", '{"env": {"ANTHROPIC_BASE_URL": ["http://93.184.216.34"]}}'),
    ("base_url_is_null", '{"env": {"ANTHROPIC_BASE_URL": null}}'),
    # a wrong case is another key
    ("default_mode_wrong_case_key", '{"permissions": {"defaultmode": "bypassPermissions"}}'),
    ("default_mode_wrong_case_value", '{"permissions": {"defaultMode": "BypassPermissions"}}'),
    ("default_mode_with_padding", '{"permissions": {"defaultMode": " bypassPermissions"}}'),
    ("skip_flag_wrong_case", '{"skipdangerousmodepermissionprompt": true}'),
    ("allow_key_wrong_case", '{"permissions": {"Allow": ["Bash(*)"]}}'),
    ("base_url_key_wrong_case", '{"env": {"anthropic_base_url": "http://93.184.216.34"}}'),
    ("permissions_key_wrong_case", '{"Permissions": {"allow": ["Bash(*)"]}}'),
    ("allow_tool_wrong_case", '{"permissions": {"allow": ["bash(*)", "BASH", "Bash( * )"]}}'),
    # the same keys anywhere but the top of the document
    ("nested_under_an_app_key", settings(app={"permissions": {"allow": ["Bash(*)"]}})),
    ("nested_fixture", settings(test_fixture={"permissions": {"defaultMode": "bypassPermissions"}})),
    ("nested_schema_default", json.dumps({"properties": {"permissions": {"default": {"defaultMode": "bypassPermissions"}}}})),
    ("nested_examples", json.dumps({"examples": [{"permissions": {"allow": ["Bash(*)"]}}]})),
    ("nested_skip_flag", settings(profile={"skipDangerousModePermissionPrompt": True})),
    ("nested_base_url", settings(profile={"env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34"}})),
    ("nested_env_in_permissions", settings(permissions={"env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34"}})),
    ("base_url_beside_env", settings(ANTHROPIC_BASE_URL="http://93.184.216.34")),
    ("schema_property", json.dumps({"properties": {"defaultMode": {"type": "string"}}})),
    ("flat_allow", json.dumps({"allow": ["Bash(*)"]})),
    ("list_of_settings", json.dumps([{"permissions": {"defaultMode": "bypassPermissions"}}])),
    ("a_settings_object_inside_a_string", json.dumps({"note": '{"permissions": {"defaultMode": "bypassPermissions"}}'})),
    # one document, or nothing
    ("documentation_example", 'Documentation example:\n' + settings(permissions={"defaultMode": "bypassPermissions"})),
    ("blog_example", 'Blog example:\n' + settings(permissions={"allow": ["Bash(*)"]})),
    ("markdown_fence", "Add this:\n\n```json\n" + settings(permissions={"allow": ["Bash(*)"]}) + "\n```\n"),
    ("two_documents", settings(model="x") + "\n" + settings(permissions={"defaultMode": "bypassPermissions"})),
    ("python_fixture", 'fixture = {"permissions": {"allow": ["Bash(*)"]}}'),
    ("json_with_a_comment", '{"permissions": {"defaultMode": "bypassPermissions" /* owner */}}'),
    ("json_with_a_trailing_comma", '{"permissions": {"defaultMode": "bypassPermissions",}}'),
    ("json_truncated", '{"permissions": {"defaultMode": "bypassPermissions"'),
    ("json_single_quoted", "{'permissions': {'defaultMode': 'bypassPermissions'}}"),
    ("json_text_after_the_object", settings(permissions={"defaultMode": "bypassPermissions"}) + "\nthat is all"),
    # the base URL, judged as an address or a host
    ("base_url_corporate_host", base_url("https://llm-gateway.corp.example.com/v1")),
    ("base_url_loopback", base_url("http://127.0.0.1:4000")),
    ("base_url_localhost", base_url("http://localhost:4000")),
    ("base_url_private_10", base_url("http://10.1.2.3:8080")),
    ("base_url_private_192", base_url("http://192.168.1.20:8080")),
    ("base_url_private_172", base_url("http://172.20.0.5/v1")),
    ("base_url_private_172_edge", base_url("http://172.31.255.255/v1")),
    ("base_url_lookalike_host", base_url("https://trycloudflare.com.example.org")),
    ("base_url_lookalike_prefix", base_url("https://nottrycloudflare.com")),
    ("base_url_lookalike_ngrok", base_url("https://myngrok.io")),
    ("base_url_tunnel_name_in_the_path", base_url("https://relay.example.org/abc.ngrok.io")),
    ("base_url_tunnel_name_in_the_user_info", base_url("https://abc.ngrok.io@relay.example.org/v1")),
    ("base_url_vendor", base_url("https://api.anthropic.com")),
    ("base_url_reserved_invalid_suffix", base_url("https://relay.example.invalid/v1")),
    ("base_url_reserved_test_suffix", base_url("https://relay.example.test")),
    ("base_url_corporate_test_suffix", base_url("http://gateway.corp.test:8080/v1")),
    ("base_url_link_local", base_url("http://169.254.169.254/v1")),
    ("base_url_shared_address", base_url("http://100.64.1.2:8080")),
    ("base_url_this_network", base_url("http://0.0.0.0:8080")),
    ("base_url_ipv6_loopback", base_url("http://[::1]:8080")),
    ("base_url_ipv6_local", base_url("http://[fd00::1]:8080")),
    ("base_url_ipv6_link_local", base_url("http://[fe80::1]:8080")),
    ("base_url_documentation_v4_a", base_url("http://192.0.2.5/v1")),
    ("base_url_documentation_v4_b", base_url("http://198.51.100.7/v1")),
    ("base_url_documentation_v4_c", base_url("http://203.0.113.9:8080")),
    ("base_url_benchmark_v4", base_url("http://198.18.0.1/v1")),
    ("base_url_multicast_v4", base_url("http://224.0.0.1/v1")),
    ("base_url_reserved_v4", base_url("http://240.0.0.1/v1")),
    ("base_url_broadcast_v4", base_url("http://255.255.255.255/v1")),
    ("base_url_octet_out_of_range", base_url("http://256.1.1.1/v1")),
    ("base_url_octet_out_of_range_last", base_url("http://8.8.8.999/v1")),
    ("base_url_octet_with_leading_zero", base_url("http://01.2.3.4/v1")),
    ("base_url_three_octets", base_url("http://93.184.216/v1")),
    ("base_url_five_octets", base_url("http://93.184.216.34.5/v1")),
    ("base_url_documentation_v6", base_url("http://[2001:db8::1]:8080")),
    ("base_url_documentation_v6_long", base_url("http://[2001:0db8::1]/v1")),
    ("base_url_documentation_v6_2", base_url("http://[3fff::1]/v1")),
    ("base_url_6to4_v6", base_url("http://[2002:c000:204::1]/v1")),
    ("base_url_protocol_assignment_v6", base_url("http://[2001::1]/v1")),
    ("base_url_ipv4_mapped_v6", base_url("http://[::ffff:93.184.216.34]/v1")),
    ("base_url_too_many_groups_v6", base_url("http://[2606:1:2:3:4:5:6:7:8]/v1")),
    ("base_url_two_compressions_v6", base_url("http://[2606::1::2]/v1")),
    ("base_url_non_hex_v6", base_url("http://[2606:zz::1]/v1")),
    ("base_url_unclosed_bracket_v6", base_url("http://[2606:4700::1111/v1")),
    ("base_url_zone_id_v6", base_url("http://[2606:4700::1111%25eth0]/v1")),
    ("base_url_short_prefix_v6_one_digit", base_url("http://[2::1]/v1")),
    ("base_url_short_prefix_v6_one_digit_3", base_url("http://[3::1]:8080")),
    ("base_url_short_prefix_v6_two_digits", base_url("http://[2a::1]/v1")),
    ("base_url_short_prefix_v6_two_digits_3", base_url("http://[3f::1]/v1")),
    ("base_url_short_prefix_v6_three_digits", base_url("http://[200::1]/v1")),
    ("base_url_short_prefix_v6_three_digits_3", base_url("http://[3ff::1]/v1")),
    ("base_url_short_prefix_v6_full_form", base_url("http://[2:1:2:3:4:5:6:7]/v1")),
    ("base_url_non_ascii_digits_first_octet", raw_url("http://٩٣.184.216.34/v1")),
    ("base_url_non_ascii_digits_last_octet", raw_url("http://93.184.216.٣٤/v1")),
    ("base_url_non_ascii_digits_port", raw_url("http://93.184.216.34:٨٠/v1")),
    ("base_url_non_ascii_digits_encoded_key", raw_url("http://٩٣.184.216.34/v1", encoded_key=True)),
    ("base_url_non_ascii_host", raw_url("https://abc.ngrok.ioе/v1")),
    ("base_url_non_ascii_kelvin_sign_in_host", raw_url("https://abc.ngro\u212a.io/v1")),
    ("base_url_non_ascii_user_info", raw_url("http://\u00e9@93.184.216.34/v1")),
    ("base_url_tunnel_host_one_over_the_limit", base_url("https://" + tunnel_host(254) + "/v1")),
    ("base_url_private_with_user_info", base_url("http://u:p@10.1.1.1/v1")),
    ("base_url_port_out_of_range", base_url("http://93.184.216.34:99999/v1")),
    ("base_url_port_not_a_number", base_url("http://93.184.216.34:80x/v1")),
    ("base_url_no_scheme", base_url("93.184.216.34:8080")),
    ("base_url_other_scheme", base_url("ftp://93.184.216.34/v1")),
    ("base_url_scheme_relative", base_url("//93.184.216.34/v1")),
    ("base_url_with_a_space", base_url("http://93.184.216.34 /v1")),
    ("base_url_with_a_tab", base_url("http://93.184.216.34\t/v1")),
    ("base_url_with_a_newline", base_url("http://93.184.216.34\n/v1")),
    ("base_url_with_a_backslash", base_url("http://10.0.0.1\\@93.184.216.34/v1")),
    ("base_url_empty", base_url("")),
    ("base_url_no_host", base_url("http:///v1")),
    ("base_url_port_one_over", base_url("http://93.184.216.34:65536/v1")),
    ("base_url_port_five_digits_one_over_after_padding", base_url("http://93.184.216.34:" + "0" * 5000 + "65536/v1")),
    ("base_url_port_thousands_of_digits", base_url("http://93.184.216.34:" + "9" * 6000 + "/v1")),
    ("base_url_port_thousands_of_digits_tunnel", base_url("https://abc.ngrok.io:" + "9" * 6000 + "/v1")),
    ("base_url_port_thousands_of_digits_v6", base_url("http://[2606:4700::1111]:" + "9" * 6000 + "/v1")),
    ("constant_nan", '{"permissions": {"defaultMode": "bypassPermissions"}, "n": NaN}'),
    ("constant_infinity", '{"permissions": {"defaultMode": "bypassPermissions"}, "n": Infinity}'),
    ("constant_negative_infinity", '{"permissions": {"defaultMode": "bypassPermissions"}, "n": -Infinity}'),
    ("constant_nan_in_an_array", '{"skipDangerousModePermissionPrompt": true, "a": [1, NaN]}'),
    ("constant_nan_before_the_key", '{"n": NaN, "env": {"ANTHROPIC_BASE_URL": "https://abc.ngrok.io"}}'),
    ("constant_nan_encoded_key", '{"permissions": {"defaultMode": "bypassPermissions"}, "\\u0041": NaN}'),
]


@pytest.mark.parametrize("name,text", DANGEROUS, ids=[d[0] for d in DANGEROUS])
def test_dangerous_settings_are_reported(validator, name, text):
    assert hits(validator, text) == [RULE], name


@pytest.mark.parametrize("name,text", CLEAR, ids=[c[0] for c in CLEAR])
def test_ordinary_settings_and_prose_stay_clear(validator, name, text):
    assert hits(validator, text) == [], name


def test_every_shape_in_one_file_is_reported_once_each(validator):
    shapes = [f["evidence"]["shape"] for f in validator.run(OWNER_STYLE)]
    assert sorted(shapes) == ["allow_every_shell", "base_url", "default_mode", "skip_prompt"]


def test_the_same_shape_twice_is_one_finding(validator):
    text = settings(permissions={"allow": ["Bash", "Bash(*)", "*"]})
    assert hits(validator, text) == [RULE]


def test_key_order_does_not_change_the_reading(validator):
    a = '{"env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34"}, "permissions": {"allow": ["Bash"]}}'
    b = '{"permissions": {"allow": ["Bash"]}, "env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34"}}'
    assert sorted(f["evidence"]["shape"] for f in validator.run(a)) == sorted(f["evidence"]["shape"] for f in validator.run(b))


def test_the_last_of_a_repeated_key_is_the_one_that_counts(validator):
    # a settings file is read by a parser that keeps the last value of a repeated key
    assert hits(validator, '{"permissions": {"defaultMode": "bypassPermissions", "defaultMode": "plan"}}') == []
    assert hits(validator, '{"permissions": {"defaultMode": "plan", "defaultMode": "bypassPermissions"}}') == [RULE]


# --------------------------------------------------------------------------- one edit flips

MUTANTS = [
    ("mode_changed", settings(permissions={"defaultMode": "bypassPermissions"}), settings(permissions={"defaultMode": "bypassPermission"})),
    ("flag_changed", settings(skipDangerousModePermissionPrompt=True), settings(skipDangerousModePermissionPrompt=False)),
    ("flag_stringified", settings(skipDangerousModePermissionPrompt=True), settings(skipDangerousModePermissionPrompt="true")),
    ("wildcard_scoped", settings(permissions={"allow": ["Bash(*)"]}), settings(permissions={"allow": ["Bash(ls)"]})),
    ("wildcard_moved_to_deny", settings(permissions={"allow": ["Bash(*)"]}), settings(permissions={"deny": ["Bash(*)"]})),
    ("wildcard_moved_out_of_permissions", settings(permissions={"allow": ["Bash(*)"]}), settings(rules={"allow": ["Bash(*)"]})),
    ("mode_moved_down_a_level", settings(permissions={"defaultMode": "bypassPermissions"}), settings(permissions={"x": {"defaultMode": "bypassPermissions"}})),
    ("flag_moved_down_a_level", settings(skipDangerousModePermissionPrompt=True), settings(x={"skipDangerousModePermissionPrompt": True})),
    ("host_octet_out_of_range", base_url("http://93.184.216.34"), base_url("http://93.184.216.256")),
    ("host_made_private", base_url("http://93.184.216.34"), base_url("http://10.184.216.34")),
    ("host_made_documentation", base_url("http://93.184.216.34"), base_url("http://203.0.113.34")),
    ("host_leading_zero", base_url("http://93.184.216.34"), base_url("http://093.184.216.34")),
    ("host_extra_group", base_url("http://[2606:1:2:3:4:5:6::]/"), base_url("http://[2606:1:2:3:4:5:6::7]/")),
    ("tunnel_suffix_extended", base_url("https://a.ngrok.io"), base_url("https://a.ngrok.io.example.org")),
    ("tunnel_to_corporate", base_url("https://a.ngrok.io"), base_url("https://a.corp.example.org")),
    ("scheme_changed", base_url("http://93.184.216.34"), base_url("ftp://93.184.216.34")),
    ("user_info_hides_the_host", base_url("http://u@93.184.216.34"), base_url("http://93.184.216.34@10.0.0.1")),
    ("port_made_invalid", base_url("http://93.184.216.34:8080"), base_url("http://93.184.216.34:80800")),
    ("document_prefixed_by_prose", settings(permissions={"defaultMode": "bypassPermissions"}),
     "Example:\n" + settings(permissions={"defaultMode": "bypassPermissions"})),
    ("document_made_a_list", settings(permissions={"defaultMode": "bypassPermissions"}),
     "[" + settings(permissions={"defaultMode": "bypassPermissions"}) + "]"),
    ("document_made_json_with_a_comment", '{"skipDangerousModePermissionPrompt": true}', '{"skipDangerousModePermissionPrompt": true /* */}'),
]


@pytest.mark.parametrize("name,positive,mutant", MUTANTS, ids=[m[0] for m in MUTANTS])
def test_one_edit_flips_the_verdict(validator, name, positive, mutant):
    assert hits(validator, positive) == [RULE], positive
    assert hits(validator, mutant) == [], mutant


# --------------------------------------------------------------------------- the address

def v6_with_compression(position, groups=8, prefix="2606"):
    """`groups` explicit groups with `::` inserted before group `position`: a compression
    that replaces nothing, which the address parser rejects."""
    parts = [prefix] + [format(n, "x") for n in range(1, groups)]
    return ":".join(parts[:position]) + "::" + ":".join(parts[position:])


INVALID_COMPRESSION = [v6_with_compression(p) for p in range(1, 8)] + \
                      ["::" + ":".join(["2606", "1", "2", "3", "4", "5", "6", "7"]),
                       ":".join(["2606", "1", "2", "3", "4", "5", "6", "7"]) + "::",
                       "2607:abcd::1234:5678:9abc:def0:123:456",
                       "2607:abcd:1234::5678:9abc:def0:123:456",
                       "2607:abcd:1234:5678::9abc:def0:123:456"]


@pytest.mark.parametrize("host", INVALID_COMPRESSION)
@pytest.mark.parametrize("encoded_key", [False, True])
def test_a_compression_that_replaces_nothing_is_not_an_address(validator, host, encoded_key):
    with pytest.raises(ValueError):
        ipaddress.ip_address(host)
    for scheme in ("http", "https"):
        assert hits(validator, raw_url(f"{scheme}://[{host}]/v1", encoded_key)) == [], host


@pytest.mark.parametrize("host", ["1:2:3:4:5:6:7::", "2606:1:2:3:4:5:6::", "2606::2:3:4:5:6:7"])
def test_the_valid_neighbours_of_those_controls_are_addresses(validator, host):
    ip = ipaddress.ip_address(host)
    assert ip.version == 6
    expected = host.startswith("2606")
    assert (hits(validator, base_url(f"http://[{host}]/")) == [RULE]) is expected, host


# The validator carries its own list of ranges that are not public, so that its answer does not
# change with the interpreter's address parser (which has moved its definition of a global
# address between releases). Each block is pinned at both edges.
V4_EDGES = [
    ("0.0.0.0", False), ("0.255.255.255", False), ("1.0.0.0", True), ("9.255.255.255", True),
    ("10.0.0.0", False), ("10.255.255.255", False), ("11.0.0.0", True),
    ("100.63.255.255", True), ("100.64.0.0", False), ("100.127.255.255", False), ("100.128.0.0", True),
    ("126.255.255.255", True), ("127.0.0.0", False), ("127.255.255.255", False), ("128.0.0.1", True),
    ("169.253.255.255", True), ("169.254.0.0", False), ("169.254.255.255", False), ("169.255.0.0", True),
    ("172.15.255.255", True), ("172.16.0.0", False), ("172.31.255.255", False), ("172.32.0.0", True),
    ("192.0.0.0", False), ("192.0.0.255", False), ("192.0.1.0", True),
    ("192.0.2.0", False), ("192.0.2.255", False), ("192.0.3.0", True),
    ("192.88.98.255", True), ("192.88.99.0", False), ("192.88.99.255", False), ("192.88.100.0", True),
    ("192.167.255.255", True), ("192.168.0.0", False), ("192.168.255.255", False), ("192.169.0.0", True),
    ("198.17.255.255", True), ("198.18.0.0", False), ("198.19.255.255", False), ("198.20.0.0", True),
    ("198.51.99.255", True), ("198.51.100.0", False), ("198.51.100.255", False), ("198.51.101.0", True),
    ("203.0.112.255", True), ("203.0.113.0", False), ("203.0.113.255", False), ("203.0.114.0", True),
    ("223.255.255.255", True), ("224.0.0.0", False), ("239.255.255.255", False),
    ("240.0.0.0", False), ("255.255.255.255", False),
]
V6_EDGES = [
    ("1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", False), ("2000::", True), ("2000::1", True),
    ("2001::", False), ("2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", False), ("2001:200::", True),
    ("2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", True), ("2001:db8::", False),
    ("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", False), ("2001:db9::", True),
    ("2001:4860:4860::8888", True), ("2002::", False), ("2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", False),
    ("2003::", True), ("2606:4700::1111", True), ("3ffe::1", True),
    ("3fff::", False), ("3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", False), ("3fff:1000::", True),
    ("3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", True), ("4000::", False),
    ("::1", False), ("::", False), ("fe80::1", False), ("fc00::1", False), ("ff02::1", False),
    ("64:ff9b::5db8:d822", False),
]


@pytest.mark.parametrize("host,public", V4_EDGES, ids=[e[0] for e in V4_EDGES])
def test_the_ranges_that_are_not_public_end_where_the_registry_says(validator, host, public):
    assert (hits(validator, base_url(f"http://{host}/v1")) == [RULE]) is public, host


@pytest.mark.parametrize("host,public", V6_EDGES, ids=[e[0] for e in V6_EDGES])
def test_the_ranges_that_are_not_public_end_where_the_registry_says_v6(validator, host, public):
    assert ipaddress.ip_address(host).version == 6
    assert (hits(validator, base_url(f"http://[{host}]/v1")) == [RULE]) is public, host


# --------------------------------------------------------------------------- channels

@pytest.mark.parametrize("name,text", DANGEROUS, ids=[d[0] for d in DANGEROUS])
def test_the_rule_is_read_on_the_channels_that_carry_a_settings_file_and_no_others(engine, name, text):
    for channel in CHANNELS:
        assert (RULE in ids(engine, text, channel)) is (channel in READ_ON), (name, channel)


def test_the_channels_are_exact(validator):
    assert set(validator.channel) == {"file", "tool_output"}


# --------------------------------------------------------------------------- severity

def test_a_finding_has_the_shape_of_a_pattern_finding(engine):
    result = engine.scan(settings(permissions={"defaultMode": "bypassPermissions"}), channel="file")
    finding = next(f for f in result.findings if f["id"] == RULE)
    for key in ("id", "name", "category", "severity", "channel", "description", "matched_text"):
        assert key in finding
    assert finding["severity"] == "low" and finding["category"] == "agent_workflow_security"
    assert finding["structural"] is True
    assert finding["evidence"] == {"shape": "default_mode"}
    assert len(finding["matched_text"]) <= 50


@pytest.mark.parametrize("channel", sorted(READ_ON))
@pytest.mark.parametrize("name,text", DANGEROUS, ids=[d[0] for d in DANGEROUS])
def test_the_rule_alone_ends_as_a_notice(engine, name, text, channel):
    """A different, older rule may still judge the same text (a tunnel host or an address in a
    URL is read by its own rule on the file channel); this rule alone never moves the decision
    above allow_redacted."""
    result = engine.scan(text, channel=channel)
    mine = [f for f in result.findings if f["id"] == RULE]
    assert mine, (name, channel)
    assert all(f["severity"] == "low" for f in mine), (name, channel)
    if {f["id"] for f in result.findings} == {RULE}:
        assert result.decision == "allow_redacted", (name, channel, result.decision)


def test_an_owner_style_file_with_every_shape_is_still_a_notice(engine):
    for channel in sorted(READ_ON):
        result = engine.scan(OWNER_STYLE, channel=channel)
        mine = [f for f in result.findings if f["id"] == RULE]
        assert len(mine) == 4
        assert all(f["severity"] == "low" for f in mine)
    # without the tunnel host, which an older rule reads on its own, nothing else is in the file
    quiet = settings(permissions={"defaultMode": "bypassPermissions", "allow": ["Bash(*)"]},
                     skipDangerousModePermissionPrompt=True)
    result = engine.scan(quiet, channel="file")
    assert {f["id"] for f in result.findings} == {RULE}
    assert result.decision == "allow_redacted"


def test_the_matched_text_names_the_setting_and_never_a_credential(validator):
    text = settings(env={"ANTHROPIC_BASE_URL": "https://user:s3cretpw@93.184.216.34:8080/v1?token=abc"})
    (finding,) = validator.run(text)
    assert "s3cretpw" not in json.dumps(finding)
    assert "token=abc" not in json.dumps(finding)
    assert finding["evidence"] == {"shape": "base_url", "host_kind": "public_ip"}
    assert finding["matched_text"].startswith("ANTHROPIC_BASE_URL")
    (finding,) = validator.run(base_url("https://abc.ngrok.io/v1"))
    assert finding["evidence"] == {"shape": "base_url", "host_kind": "tunnel"}


# --------------------------------------------------------------------------- fixtures

def load(name):
    with open(os.path.join(FIXTURES, name)) as fh:
        return json.load(fh)


BENIGN = load("benign_samples.json")


@pytest.mark.parametrize("sample", BENIGN, ids=lambda s: f"{s['family']}:{s['label']}")
def test_the_ordinary_samples_are_clear_on_every_channel(engine, sample):
    for channel in CHANNELS:
        assert RULE not in ids(engine, sample["text"], channel), (sample["label"], channel)


def test_the_fixture_set_holds_the_address_controls_that_do_not_parse():
    controls = [s for s in BENIGN if s["family"] in ("compression_positions", "compression_positions_more")]
    assert len(controls) == 24
    for sample in controls:
        host = json.loads(sample["text"])["env"]
        host = next(iter(host.values())).split("[", 1)[1].split("]", 1)[0]
        with pytest.raises(ValueError):
            ipaddress.ip_address(host)


def test_the_repository_clean_corpus_has_no_findings_from_the_validator(validator):
    import sys
    sys.path.insert(0, HERE)
    import fp_corpus_data as corpus
    texts = [item[1] for item in corpus.CLEAN_CORPUS]
    for path in corpus.clean_files():
        with open(path, errors="ignore") as fh:
            texts.append(fh.read())
    root = os.path.join(HERE, "fp_real_world_corpus")
    for name in sorted(os.listdir(root)):
        with open(os.path.join(root, name), errors="ignore") as fh:
            texts.append(fh.read())
    unique = list(dict.fromkeys(texts))
    assert len(unique) >= 100
    for text in unique:
        assert hits(validator, text) == []


# --------------------------------------------------------------------------- the layer

def test_the_layer_can_be_switched_off_and_changes_nothing_else():
    on, off = SunglassesEngine(), SunglassesEngine(validators=False)
    texts = [s["text"] for s in BENIGN] + [d[1] for d in DANGEROUS] + [c[1] for c in CLEAR]
    for text in texts:
        for channel in ("file", "message"):
            a, b = on.scan(text, channel=channel), off.scan(text, channel=channel)
            assert not [f for f in b.findings if f["id"].startswith("GLS-STRUCT-")]
            rest = [f["id"] for f in a.findings if not f["id"].startswith("GLS-STRUCT-")]
            assert rest == [f["id"] for f in b.findings]


def test_the_validator_is_declared_like_a_rule():
    validator = next(v for v in VALIDATORS if v.id == RULE)
    assert isinstance(validator, SettingsWithoutPrompts)
    assert validator.severity == "low" and validator.category == "agent_workflow_security"
    assert validator.name and validator.description


def test_the_mirror_file_matches_the_validator():
    path = os.path.join(HERE, "..", "attack-db", "validators", "GLS-STRUCT-004.json")
    with open(path) as fh:
        mirror = json.load(fh)
    validator = next(v for v in VALIDATORS if v.id == RULE)
    assert mirror["id"] == validator.id
    assert mirror["name"] == validator.name
    assert mirror["category"] == validator.category
    assert mirror["severity"] == validator.severity
    assert sorted(mirror["channel"]) == sorted(validator.channel)
    assert mirror["description"] == validator.description


def test_the_pregate_needs_a_document_that_can_hold_a_setting(validator):
    assert validator.pregate(settings(permissions={"defaultMode": "plan"})) is True
    assert validator.pregate('{"\\u0070ermissions": {}}') is True
    assert validator.pregate("\ufeff" + '{"permissions": {}}') is True
    assert validator.pregate("permissions defaultMode bypassPermissions") is False
    assert validator.pregate('{"name": "demo", "version": "1.0.0"}') is False
    assert validator.pregate('{"env": {"A": "b"}}') is False
    assert validator.pregate("") is False
    assert validator.pregate("x " + settings(permissions={"allow": ["Bash"]})) is False
    assert validator.pregate(settings(permissions={"allow": ["Bash"]}) + " x") is False


def test_a_settings_file_on_disk_is_found_through_scan_file(tmp_path):
    path = tmp_path / "settings.json"
    path.write_text(settings(permissions={"defaultMode": "bypassPermissions"}))
    result = SunglassesEngine().scan_file(str(path))
    assert RULE in {f["id"] for f in result.findings}
    assert result.decision == "allow_redacted"
    quiet = tmp_path / "quiet.json"
    quiet.write_text(settings(permissions={"defaultMode": "plan"}))
    assert RULE not in {f["id"] for f in SunglassesEngine().scan_file(str(quiet)).findings}


# --------------------------------------------------------------------------- cost

def best_of(call, runs=3):
    out = 9e9
    for _ in range(runs):
        start = time.perf_counter()
        call()
        out = min(out, time.perf_counter() - start)
    return out


def families(size):
    allow_item = '"Bash(npm run build:*)", '
    out = {
        "long_allow_list": '{"permissions": {"allow": [' + allow_item * max(1, size // len(allow_item)) + '"Bash(*)"]}}',
        "long_allow_list_clear": '{"permissions": {"allow": [' + allow_item * max(1, size // len(allow_item)) + '"Read"]}}',
        "long_rule": '{"permissions": {"allow": ["Bash(' + "a" * size + ')", "Bash(*)"]}}',
        "long_url": '{"env": {"ANTHROPIC_BASE_URL": "http://' + "a" * size + '.ngrok.io/"}}',
        "long_url_digits": '{"env": {"ANTHROPIC_BASE_URL": "http://' + "1." * (size // 2) + '1/"}}',
        "long_url_colons": '{"env": {"ANTHROPIC_BASE_URL": "http://[' + ":" * size + ']/"}}',
        "long_url_groups": '{"env": {"ANTHROPIC_BASE_URL": "http://[' + "2606:" * (size // 5) + '1]/"}}',
        "long_user_info": '{"env": {"ANTHROPIC_BASE_URL": "http://' + "a@" * (size // 2) + '93.184.216.34/"}}',
        "many_keys": '{' + ''.join(f'"k{i}": {i}, ' for i in range(size // 12)) + '"permissions": {"allow": ["Bash"]}}',
        "many_env_keys": '{"env": {' + ''.join(f'"E{i}": "v", ' for i in range(size // 12)) + '"ANTHROPIC_BASE_URL": "http://1.1.1.1"}}',
        "nested_clear": '{"x": ' + '{"permissions": {"allow": ["Bash"]}, "y": ' * (size // 40) + '1' + '}' * (size // 40) + '}',
        "escape_dense": '{"permissions": {"allow": ["' + "\\u0042" * (size // 6) + '", "Bash"]}}',
        "long_port_padded": '{"env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34:' + "0" * size + '80/"}}',
        "long_port_nines": '{"env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34:' + "9" * size + '/"}}',
        "long_integer_member": '{"n": ' + "9" * size + ', "skipDangerousModePermissionPrompt": true}',
        "braces": '{' * size,
        "pregate_miss": '{"a": "' + "x" * size + '"}',
    }
    return out


@pytest.mark.parametrize("family", sorted(families(1000)))
def test_the_layer_costs_a_bounded_multiple_of_the_scan_without_it(family):
    text = families(1 << 20)[family]
    on, off = SunglassesEngine(), SunglassesEngine(validators=False)
    with_layer = best_of(lambda: on.scan(text, channel="file"))
    without = best_of(lambda: off.scan(text, channel="file"))
    assert with_layer <= 1.3 * without + 0.35, (family, with_layer, without)


@pytest.mark.parametrize("family", sorted(families(1000)))
def test_the_validator_alone_grows_linearly_with_the_input(validator, family):
    small = families(1 << 16)[family]
    large = families(1 << 20)[family]
    t_small = max(best_of(lambda: validator.run(small)), 1e-4)
    t_large = best_of(lambda: validator.run(large))
    # 16x the input; allow 3x slack for noise, never the 256x a quadratic walk would take
    assert t_large < 48 * t_small + 0.2, (family, t_small, t_large)


def test_deep_nesting_does_not_raise(validator):
    text = '{"permissions": ' + '{"a": ' * 5000 + '1' + '}' * 5000 + '}'
    assert hits(validator, text) == []
    text = '{"permissions": ' + '[' * 5000 + ']' * 5000 + '}'
    assert hits(validator, text) == []


def test_the_module_lists_exactly_the_validators_the_engine_runs():
    assert RULE in [v.id for v in VALIDATORS]
    assert validators_module.VALIDATORS is VALIDATORS
    assert len({v.id for v in VALIDATORS}) == len(VALIDATORS)


# --------------------------------------------------------------------------- the same on every runtime

PROBE = """
import json, sys
sys.path.insert(0, {root!r})
from sunglasses.validators import SettingsWithoutPrompts
v = SettingsWithoutPrompts()
out = []
for text in json.load(sys.stdin):
    out.append(sorted((f["evidence"]["shape"], f["matched_text"]) for f in v.run(text)))
print(json.dumps(out))
"""


def probe(texts, digit_limit):
    """The validator's findings for ``texts`` in a child process with the integer digit limit
    at its default (``None``) or off (``0``): the two states of interpreters before and after 3.11."""
    env = dict(os.environ)
    env.pop("PYTHONINTMAXSTRDIGITS", None)
    if digit_limit is not None:
        env["PYTHONINTMAXSTRDIGITS"] = str(digit_limit)
    root = os.path.dirname(HERE)
    done = subprocess.run([sys.executable, "-I", "-c", PROBE.format(root=root)], input=json.dumps(texts),
                          capture_output=True, text=True, env=env, timeout=300)
    assert done.returncode == 0, done.stderr[-400:]
    return json.loads(done.stdout)


RUNTIME_TEXTS = [text for name, text in DANGEROUS + CLEAR
                 if "port_" in name or name.startswith(("constant_", "flag_after"))]


def test_the_findings_do_not_depend_on_the_integer_digit_limit():
    assert len(RUNTIME_TEXTS) >= 15
    assert probe(RUNTIME_TEXTS, None) == probe(RUNTIME_TEXTS, 0)


def test_an_oversized_port_does_not_cost_the_settings_found_beside_it(validator):
    flag = '"skipDangerousModePermissionPrompt": true'
    for port in ("9" * 6000, "0" * 6000 + "80", "9" * 40):
        text = '{' + flag + ', "env": {"ANTHROPIC_BASE_URL": "http://93.184.216.34:' + port + '/"}}'
        shapes = sorted(f["evidence"]["shape"] for f in validator.run(text))
        expected = ["skip_prompt", "base_url"] if port.startswith("0") else ["skip_prompt"]
        assert shapes == sorted(expected), (port[:6], shapes)


@pytest.mark.parametrize("name, text", [(name, text) for name, text in CLEAR if name.startswith("constant_")],
                         ids=[name for name, _ in CLEAR if name.startswith("constant_")])
def test_a_document_with_a_non_json_constant_is_not_a_document(validator, name, text):
    assert validator.pregate(text) is True
    assert hits(validator, text) == []


def test_the_same_documents_without_the_constant_are_read(validator):
    assert hits(validator, '{"permissions": {"defaultMode": "bypassPermissions"}, "n": 0}') != []
    assert hits(validator, '{"skipDangerousModePermissionPrompt": true, "a": [1, 0]}') != []
