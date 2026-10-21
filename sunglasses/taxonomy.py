"""Where each Sunglasses attack category sits in three public frameworks.

A finding's `category` is mapped, at the category level, to:

  * the OWASP Top 10 for LLM Applications (2025 edition),
  * MITRE ATLAS techniques (data release 2026.09),
  * NIST AI RMF 1.0 (AI 100-1) subcategories and Generative AI Profile (AI 600-1) risks.

WHAT THIS IS, AND IS NOT. The mapping is by category, so every finding in a category
inherits the same entries. It says "this kind of attack is discussed under these headings",
not "this finding is a confirmed instance of that technique". One category can touch more
than one heading, and a few headings are a loose fit for a category; the entries chosen are
the closest ones that exist in the published lists, and nothing here invents an identifier.
Every id and name below is copied from the source named in SOURCES (a subtechnique's name is
prefixed with its parent's, "LLM Prompt Injection: Direct", because ATLAS names it by one word;
the dashes in the two RMF subcategory names are ASCII). When a source publishes
a new edition, the table is re-checked by hand against it; it is data, not detection, and
changing it never changes a verdict.

Each source carries a fixed GUID. SARIF identifies a taxonomy component by it, so a SARIF
reader can resolve a rule's link to the component in the same run without matching names. The
GUIDs are random constants chosen once; they stay the same until a source's version changes.

The table is plain data on purpose: it is read at output time to annotate findings and is
never consulted by the scanner when it decides anything.
"""

SOURCES = {
    "owasp_llm_top10": {
        "name": "OWASP Top 10 for LLM Applications",
        "short_name": "OWASP LLM Top 10",
        "organization": "OWASP",
        "version": "2025",
        "guid": "b3a2f5c1-6d4e-4f0a-9c27-1e8d5a7b3c01",
        "url": "https://genai.owasp.org/llm-top-10/",
    },
    "mitre_atlas": {
        "name": "MITRE ATLAS",
        "short_name": "MITRE ATLAS",
        "organization": "MITRE",
        "version": "2026.09",
        "guid": "7e91c4d8-2a35-4b6f-8d10-5c3f9a2e6b02",
        "url": "https://github.com/mitre-atlas/atlas-data/blob/v2026.09/dist/ATLAS-latest.yaml",
    },
    "nist_ai": {
        "name": "NIST AI RMF 1.0 (AI 100-1) and Generative AI Profile (AI 600-1)",
        "short_name": "NIST AI RMF",
        "organization": "NIST",
        "version": "AI 100-1 January 2023; AI 600-1 July 2024",
        "guid": "d40f8a63-9b17-4e52-a6c8-3f1b7e5d9c03",
        "url": "https://doi.org/10.6028/NIST.AI.600-1",
    },
}

_OWASP_PAGE = "https://genai.owasp.org/llmrisk/"

# id -> (title, page slug under _OWASP_PAGE)
OWASP_LLM_TOP10 = {
    "LLM01": ("Prompt Injection", "llm01-prompt-injection"),
    "LLM02": ("Sensitive Information Disclosure", "llm022025-sensitive-information-disclosure"),
    "LLM03": ("Supply Chain", "llm032025-supply-chain"),
    "LLM04": ("Data and Model Poisoning", "llm042025-data-and-model-poisoning"),
    "LLM05": ("Improper Output Handling", "llm052025-improper-output-handling"),
    "LLM06": ("Excessive Agency", "llm062025-excessive-agency"),
    "LLM07": ("System Prompt Leakage", "llm072025-system-prompt-leakage"),
    "LLM08": ("Vector and Embedding Weaknesses", "llm082025-vector-and-embedding-weaknesses"),
    "LLM10": ("Unbounded Consumption", "llm102025-unbounded-consumption"),
}

# id -> technique name
MITRE_ATLAS = {
    "AML.T0010": "AI Supply Chain Compromise",
    "AML.T0010.003": "AI Supply Chain Compromise: Model",
    "AML.T0011.001": "User Execution: Malicious Package",
    "AML.T0011.002": "User Execution: Poisoned AI Agent Tool",
    "AML.T0018": "Manipulate AI Model",
    "AML.T0018.003": "Manipulate AI Model: Modify Prompt Construction Logic",
    "AML.T0025": "Exfiltration via Cyber Means",
    "AML.T0029": "Denial of AI Service",
    "AML.T0034.001": "Cost Harvesting: Resource-Intensive Queries",
    "AML.T0049": "Exploit Public-Facing Application",
    "AML.T0050": "Command and Scripting Interpreter",
    "AML.T0051": "LLM Prompt Injection",
    "AML.T0051.000": "LLM Prompt Injection: Direct",
    "AML.T0051.001": "LLM Prompt Injection: Indirect",
    "AML.T0052": "Phishing",
    "AML.T0053": "AI Agent Tool Invocation",
    "AML.T0054": "LLM Jailbreak",
    "AML.T0055": "Unsecured Credentials",
    "AML.T0056": "Extract LLM System Prompt",
    "AML.T0057": "LLM Data Leakage",
    "AML.T0066": "Retrieval Content Crafting",
    "AML.T0067": "LLM Trusted Output Components Manipulation",
    "AML.T0068": "LLM Prompt Obfuscation",
    "AML.T0069": "Discover LLM System Information",
    "AML.T0069.002": "Discover LLM System Information: System Prompt",
    "AML.T0070": "RAG Poisoning",
    "AML.T0071": "False RAG Entry Injection",
    "AML.T0072": "Cyber Communication Channel",
    "AML.T0073": "Impersonation",
    "AML.T0077": "LLM Response Rendering",
    "AML.T0080": "AI Agent Context Poisoning",
    "AML.T0080.000": "AI Agent Context Poisoning: Memory",
    "AML.T0081": "Modify AI Agent Configuration",
    "AML.T0086": "Exfiltration via AI Agent Tool Invocation",
    "AML.T0091": "Use Alternate Authentication Material",
    "AML.T0098": "AI Agent Tool Credential Harvesting",
    "AML.T0099": "AI Agent Tool Data Poisoning",
    "AML.T0102": "Generate Malicious Commands",
    "AML.T0105": "Escape to Host",
    "AML.T0110": "AI Agent Tool Poisoning",
    "AML.T0118": "Autonomous AI Agent Communication",
    "AML.T0118.001": "Autonomous AI Agent Communication: Direct Agent Communication",
    "AML.T0119": "Exploit Automated Artifact Processing Pipeline",
}

# id -> name of the risk or subcategory
NIST_AI = {
    "NIST AI 600-1 2.12": "Value Chain and Component Integration",
    "NIST AI 600-1 2.4": "Data Privacy",
    "NIST AI 600-1 2.9": "Information Security",
    "NIST AI RMF 1.0 MEASURE 2.10": "Privacy risk of the AI system - as identified in the MAP function - is examined and documented",
    "NIST AI RMF 1.0 MEASURE 2.7": "AI system security and resilience - as identified in the MAP function - are evaluated and documented",
}

# Shared shapes: (OWASP ids, ATLAS ids, NIST ids). A category names one of these below.
_PROFILES = {
    "INJ": (
        ("LLM01",),
        ("AML.T0051", "AML.T0051.000",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "INDIRECT": (
        ("LLM01",),
        ("AML.T0051", "AML.T0051.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "JAILBREAK": (
        ("LLM01",),
        ("AML.T0054",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "OBFUSC": (
        ("LLM01",),
        ("AML.T0068",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "HIDDEN": (
        ("LLM01",),
        ("AML.T0051.001", "AML.T0068",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "PROMPTLEAK": (
        ("LLM07",),
        ("AML.T0056", "AML.T0069.002",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "EXFIL": (
        ("LLM02",),
        ("AML.T0057", "AML.T0086",),
        ("NIST AI 600-1 2.4", "NIST AI RMF 1.0 MEASURE 2.10",),
    ),
    "CHANNEL": (
        ("LLM02",),
        ("AML.T0072", "AML.T0025",),
        ("NIST AI 600-1 2.4", "NIST AI RMF 1.0 MEASURE 2.10",),
    ),
    "SECRET": (
        ("LLM02",),
        ("AML.T0055", "AML.T0098",),
        ("NIST AI 600-1 2.4", "NIST AI RMF 1.0 MEASURE 2.10",),
    ),
    "ERRLEAK": (
        ("LLM02",),
        ("AML.T0057", "AML.T0069",),
        ("NIST AI 600-1 2.4", "NIST AI RMF 1.0 MEASURE 2.10",),
    ),
    "COMMAND": (
        ("LLM05", "LLM06",),
        ("AML.T0050", "AML.T0102",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "WEBINPUT": (
        ("LLM05",),
        ("AML.T0053", "AML.T0049",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "SANDBOX": (
        ("LLM06",),
        ("AML.T0105",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "AGENCY": (
        ("LLM06",),
        ("AML.T0053",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "AUTHMAT": (
        ("LLM06",),
        ("AML.T0091",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "IMPERSONATE": (
        ("LLM01",),
        ("AML.T0073",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "PHISH": (
        ("LLM01",),
        ("AML.T0052", "AML.T0073",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "UIRENDER": (
        ("LLM05",),
        ("AML.T0077", "AML.T0067",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "UIPHISH": (
        ("LLM01",),
        ("AML.T0052", "AML.T0077",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "TOOLPOISON": (
        ("LLM01", "LLM06",),
        ("AML.T0110", "AML.T0011.002",),
        ("NIST AI 600-1 2.9", "NIST AI 600-1 2.12", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "TOOLOUTPUT": (
        ("LLM01",),
        ("AML.T0099", "AML.T0051.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "MEMORY": (
        ("LLM01", "LLM04",),
        ("AML.T0080", "AML.T0080.000",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "CONTEXT": (
        ("LLM01",),
        ("AML.T0080", "AML.T0051.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "RAG": (
        ("LLM08", "LLM04",),
        ("AML.T0070", "AML.T0071", "AML.T0066",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "CROSSAGENT": (
        ("LLM01", "LLM06",),
        ("AML.T0118", "AML.T0118.001", "AML.T0051.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "CONFIGFILE": (
        ("LLM01",),
        ("AML.T0081", "AML.T0051.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "TEMPLATE": (
        ("LLM01",),
        ("AML.T0018.003", "AML.T0051",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "ROUTING": (
        ("LLM01",),
        ("AML.T0081",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "PROMPTLOGIC": (
        ("LLM01",),
        ("AML.T0051",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "SUPPLY": (
        ("LLM03",),
        ("AML.T0010", "AML.T0011.001",),
        ("NIST AI 600-1 2.12", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "ATTEST": (
        ("LLM03",),
        ("AML.T0010",),
        ("NIST AI 600-1 2.12", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "PIPELINE": (
        ("LLM03",),
        ("AML.T0010", "AML.T0119",),
        ("NIST AI 600-1 2.12", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "MLOPS": (
        ("LLM03", "LLM04",),
        ("AML.T0010.003", "AML.T0018",),
        ("NIST AI 600-1 2.12", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "DOS": (
        ("LLM10",),
        ("AML.T0029", "AML.T0034.001",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
    "WORKFLOW": (
        ("LLM01", "LLM06",),
        ("AML.T0053", "AML.T0051",),
        ("NIST AI 600-1 2.9", "NIST AI RMF 1.0 MEASURE 2.7",),
    ),
}

# category (as the scanner emits it) -> profile
_CATEGORY_PROFILE = {
    "a2a_capability_escalation": "CROSSAGENT",
    "a2a_card_metadata_injection": "CROSSAGENT",
    "agent_contract_poisoning": "CROSSAGENT",
    "agent_instruction_file_poisoning": "CONFIGFILE",
    "agent_persona_drift": "PROMPTLOGIC",
    "agent_protocol_state": "CROSSAGENT",
    "agent_security": "WORKFLOW",
    "agent_workflow": "WORKFLOW",
    "agent_workflow_security": "WORKFLOW",
    "api_descriptor_poisoning": "TOOLPOISON",
    "approval_graph_poisoning": "AGENCY",
    "attestation_lineage_poisoning": "ATTEST",
    "audit_log_tool_output": "TOOLOUTPUT",
    "auth_bypass": "AGENCY",
    "authority_inversion": "IMPERSONATE",
    "authorization_bypass": "AGENCY",
    "billing_tool_output_poisoning": "TOOLOUTPUT",
    "browser_retrieval_metadata": "RAG",
    "browser_runtime_cache": "CONTEXT",
    "browser_runtime_state": "CONTEXT",
    "browser_tool_output_injection": "TOOLOUTPUT",
    "browser_tool_output_poisoning": "TOOLOUTPUT",
    "build_metadata_poisoning": "PIPELINE",
    "c2_indicator": "CHANNEL",
    "ci_diagnostic_poisoning": "TOOLOUTPUT",
    "cicd_metadata_poisoning": "PIPELINE",
    "cloud_auth_tool_output": "TOOLOUTPUT",
    "cloudflare_access_audit_log_tool_output": "TOOLOUTPUT",
    "code_injection": "WEBINPUT",
    "code_switching": "OBFUSC",
    "coercion": "PROMPTLOGIC",
    "command_injection": "COMMAND",
    "compaction_artifact_spoofing": "MEMORY",
    "configuration_management_preview_output": "TOOLOUTPUT",
    "context_flooding": "PROMPTLOGIC",
    "cross_agent_injection": "CROSSAGENT",
    "delegated_approval_rebinding": "AGENCY",
    "delegation_boundary_poisoning": "AGENCY",
    "delegation_bridge_state_laundering": "CROSSAGENT",
    "denial_of_ai_service": "DOS",
    "dependency_automation_metadata": "PIPELINE",
    "deployment_template_poisoning": "TEMPLATE",
    "deserialization": "WEBINPUT",
    "discovery_file_poisoning": "CONFIGFILE",
    "dns_tunneling": "CHANNEL",
    "duplicate_key_shadowing": "OBFUSC",
    "encoded_payload": "OBFUSC",
    "encoding_evasion": "OBFUSC",
    "encoding_smuggling": "OBFUSC",
    "error_message_leakage": "ERRLEAK",
    "exfiltration": "EXFIL",
    "hidden_instruction": "HIDDEN",
    "identity_discovery_poisoning": "IMPERSONATE",
    "identity_federation": "IMPERSONATE",
    "identity_phishing": "PHISH",
    "indirect_prompt_injection": "INDIRECT",
    "invisible_unicode": "OBFUSC",
    "jailbreak": "JAILBREAK",
    "jailbreak_evasion": "JAILBREAK",
    "long_context_exploitation_policy_pivot": "PROMPTLOGIC",
    "mcp_sampling_hijack": "TOOLPOISON",
    "mcp_threat": "TOOLPOISON",
    "mcp_tool_injection": "TOOLPOISON",
    "memory_eviction_rehydration": "MEMORY",
    "memory_poisoning": "MEMORY",
    "memory_retrieval": "MEMORY",
    "memory_state_replay": "MEMORY",
    "migration_tool_output_poisoning": "TOOLOUTPUT",
    "mlops_metadata_poisoning": "MLOPS",
    "model_routing_confusion": "ROUTING",
    "multi_stage_encoding": "OBFUSC",
    "observability_tool_output_poisoning": "TOOLOUTPUT",
    "oidc_credential_endpoint_substitution": "AUTHMAT",
    "parasitic_injection": "INJ",
    "path_traversal": "WEBINPUT",
    "policy_scope_redefinition": "PROMPTLOGIC",
    "privilege_escalation": "AGENCY",
    "prompt_extraction": "PROMPTLEAK",
    "prompt_injection": "INJ",
    "prompt_leak": "PROMPTLEAK",
    "provenance_chain": "CROSSAGENT",
    "provenance_chain_fracture": "CROSSAGENT",
    "rag_metadata_field_injection": "RAG",
    "repo_metadata_poisoning": "CONFIGFILE",
    "representation_parser_differential": "OBFUSC",
    "retrieval_poisoning": "RAG",
    "retrieval_provenance_decay_authority_laundering": "RAG",
    "rtl_obfuscation": "OBFUSC",
    "runtime_config_metadata_poisoning": "CONFIGFILE",
    "sampling_parameter_injection": "ROUTING",
    "sandbox_escape": "SANDBOX",
    "secret_detection": "SECRET",
    "semantic_cache_authority_laundering": "RAG",
    "social_engineering": "IMPERSONATE",
    "social_engineering_ui": "UIPHISH",
    "speculative_decode_hijack": "ROUTING",
    "sql_injection": "WEBINPUT",
    "ssrf": "WEBINPUT",
    "state_sync_poisoning": "CROSSAGENT",
    "structured_metadata_poisoning": "CONFIGFILE",
    "supply_chain": "SUPPLY",
    "supply_chain_attestation_poisoning": "ATTEST",
    "template_format_injection": "TEMPLATE",
    "template_metadata_poisoning": "TEMPLATE",
    "terminal_output_encoding_smuggling": "OBFUSC",
    "token_smuggling": "OBFUSC",
    "tool_cache_poisoning": "TOOLOUTPUT",
    "tool_chain_race": "AGENCY",
    "tool_metadata_smuggling": "TOOLPOISON",
    "tool_output_injection": "TOOLOUTPUT",
    "tool_output_poisoning": "TOOLOUTPUT",
    "tool_output_provenance_swap": "TOOLOUTPUT",
    "tool_output_receipt_poisoning": "TOOLOUTPUT",
    "tool_poisoning": "TOOLPOISON",
    "tool_response_spoofing": "TOOLOUTPUT",
    "tool_schema_default_fallback": "TOOLPOISON",
    "ui_injection": "UIRENDER",
    "unicode_evasion": "OBFUSC",
    "vector_metadata_instruction_smuggling": "RAG",
    "workflow_orchestrator_tool_output": "TOOLOUTPUT",
}


def categories():
    """Every category that has a row, sorted."""
    return tuple(sorted(_CATEGORY_PROFILE))


def owasp_url(taxon_id):
    return _OWASP_PAGE + OWASP_LLM_TOP10[taxon_id][1] + "/"


def for_category(category):
    """The three lists for one category, as plain data a JSON writer can emit.

    A category with no row (including the "unknown" a finding gets when it carries none)
    returns three empty lists, so a consumer never has to test for the key.
    """
    profile = _PROFILES.get(_CATEGORY_PROFILE.get(category))
    if profile is None:
        return {"owasp_llm_top10": [], "mitre_atlas": [], "nist_ai": []}
    owasp, atlas, nist = profile
    return {
        "owasp_llm_top10": [{"id": i, "name": OWASP_LLM_TOP10[i][0]} for i in owasp],
        "mitre_atlas": [{"id": i, "name": MITRE_ATLAS[i]} for i in atlas],
        "nist_ai": [{"id": i, "name": NIST_AI[i]} for i in nist],
    }
