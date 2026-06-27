"""fp_corpus_data.py — THE single source for Sunglasses' clean-FP corpus.

Pure data + stdlib (json, os). NO pytest, NO engine import — so fp_gate (and thus
Pattern-Forge inside Jack's pytest-less container) loads the corpus with zero test
deps. The FP test modules and fp_gate all import FROM here. Extracted Jun 12 2026
(Opus 4.8) per F5 warroom ruling — decouples the gate from pytest (forge hard-rule #2:
runs in-container unmodified). Stdlib only, no new deps. 🇺🇸
"""
import json
import os

CLEAN_CORPUS = [
    ("readme_install",
     "# MyProject\n\nThis project provides tools for data analysis.\n\n"
     "## Installation\n\n```\npip install myproject\n```\n\n## Setup\n\n"
     "Download the config and run the setup wizard in your terminal.", "file"),
    ("readme_prereq",
     "## Prerequisites\n\nBefore installation, download Python 3.11. Open a "
     "terminal and paste the command to run the installer.", "file"),
    ("webpage_simple",
     "<html><body><h1>Welcome</h1><p>This is a normal web page about cooking "
     "recipes.</p></body></html>", "web_content"),
    ("webpage_blog",
     "<html><head><title>Blog</title></head><body><article><h1>My trip</h1>"
     "<p>We visited the model village and saw a robot.</p></article></body>"
     "</html>", "web_content"),
    ("tech_discussion",
     "The system prompt is an important concept in LLM applications. Here's "
     "how to design one for your AI agent.", "message"),
    ("security_article",
     "Prompt injection is a growing concern. Researchers are developing "
     "detection methods for command injection and SSRF.", "message"),
    ("security_article2",
     "This article explains how jailbreak attempts and developer mode "
     "exploits work, so you can defend against them.", "message"),
    ("apikey_safe",
     "You can find your API key in the dashboard under Settings > API Keys. "
     "Keep your token and secret safe.", "message"),
    ("apikey_safe_bearer",
     "To authenticate, pass your API key as a bearer token in the "
     "Authorization header.", "message"),
    ("css_file",
     "body { font-size: 16px; color: #333; background: white; }", "file"),
    ("json_api",
     '{"status": "ok", "data": {"temperature": 72, "humidity": 45}, '
     '"model": "v2", "timestamp": "2026-03-28"}', "api_response"),
    ("polite_question",
     "Can you help me write a Python function to sort a list?", "message"),
    ("code_review_req",
     "Please review this code and suggest improvements for error handling.",
     "message"),
    ("legit_memory",
     "Remember: the user prefers dark mode and wants responses in bullet "
     "points.", "log_memory"),
    ("partial_keyword",
     "Please review my previous work on the instruction manual.", "message"),
    ("devops_doc",
     "Our CI runs the build, then deploys. We use a redirect for the old URL "
     "and an HTTP health check.", "message"),
    ("code_subprocess",
     "import os\ndef run(cmd):\n    return subprocess.run(cmd, check=True)  "
     "# internal helper, trusted input only", "file"),
    ("oauth_doc",
     "OAuth lets a third-party application access your account with read-only "
     "scope without sharing your password.", "message"),
    ("git_doc",
     "To contribute, fork the repo, create a branch, and open a pull request. "
     "A maintainer will review and merge it.", "message"),
    ("mcp_doc",
     "An MCP server exposes tools to an AI assistant. The model calls a tool "
     "and the server returns a response.", "message"),
    ("eval_word",
     "We need to evaluate the candidates and do a performance eval next "
     "quarter.", "message"),
    ("exec_word",
     "The executive team and the exec assistant will join the meeting about "
     "the new model launch.", "message"),
    ("pkg_doc",
     "After installation, import the package and call the main function. See "
     "setup.py for dependencies.", "file"),
    ("crawler_doc",
     "Our web crawler indexes pages for the search bot. The provider_url "
     "field points to the oembed endpoint.", "file"),
    # ── Discovery files — NORMAL ones. A scanner that blocks a plain robots.txt
    #    or security.txt is the exact embarrassment the discovery_file_poisoning
    #    category warns against. Added Jun 6 2026 (v0.2.62 FP fix).
    ("clean_robots_txt",
     "User-agent: *\nDisallow: /admin/\nDisallow: /private/\nAllow: /public/\n"
     "Crawl-delay: 10\n\nUser-agent: Googlebot\nAllow: /\n\n"
     "Sitemap: https://example.com/sitemap.xml", "file"),
    ("clean_llms_txt",
     "# Example Corp\n\n> Example Corp builds developer tools for API "
     "monitoring.\n\n## Docs\n- [Getting Started](https://example.com/docs/start): "
     "How to install and configure.\n- [API Reference](https://example.com/docs/api): "
     "Full endpoint reference.", "file"),
    ("clean_security_txt",
     "Contact: mailto:security@example.com\nExpires: 2026-12-31T23:59:59.000Z\n"
     "Encryption: https://example.com/pgp-key.txt\nPreferred-Languages: en, es\n"
     "Canonical: https://example.com/.well-known/security.txt\n"
     "Policy: https://example.com/security-policy", "file"),
    ("clean_sitemap_xml",
     '<?xml version="1.0" encoding="UTF-8"?>\n'
     '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
     '  <url><loc>https://example.com/</loc><priority>1.0</priority></url>\n'
     '  <url><loc>https://example.com/about</loc><priority>0.8</priority></url>\n'
     '</urlset>', "file"),
    ("clean_ai_plugin_json",
     '{"schema_version": "v1", "name_for_human": "Example Weather", '
     '"name_for_model": "weather", "description_for_human": "Get the weather '
     'forecast.", "description_for_model": "Plugin for getting current weather '
     'and forecasts by city.", "contact_email": "support@example.com"}', "file"),
    ("clean_humans_txt",
     "/* TEAM */\nDeveloper: Jane Doe\nSite: jane@example.com\nLocation: San "
     "Diego, CA\n\n/* THANKS */\nOpen source community\n\n/* SITE */\n"
     "Standards: HTML5, CSS3\nComponents: React, Node.js", "file"),
    # ── Structured-metadata files — NORMAL ones. The SMP patterns (v0.2.68)
    #    blocked these clean files via bare format-name keywords (sbom, json-ld,
    #    schema.org, jsonfeed.org/version, etc.). Added Jun 19 2026 with the
    #    KEYWORD_DENYLIST fix so the FP gate is no longer blind to these channels.
    ("clean_cyclonedx_sbom",
     '{"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1, '
     '"components": [{"type": "library", "name": "express", "version": "4.18.2", '
     '"purl": "pkg:npm/express@4.18.2"}, {"type": "library", "name": "lodash", '
     '"version": "4.17.21"}]}', "file"),
    ("clean_json_ld",
     '<script type="application/ld+json">\n{"@context": "https://schema.org", '
     '"@type": "Organization", "name": "Example Corp", "url": '
     '"https://example.com", "logo": "https://example.com/logo.png"}\n</script>',
     "file"),
    ("clean_json_feed",
     '{"version": "https://jsonfeed.org/version/1.1", "title": "My Blog", '
     '"home_page_url": "https://example.com/", "items": [{"id": "1", "title": '
     '"First post", "content_text": "Welcome to my blog about AI agents."}]}',
     "file"),
    ("clean_codemeta",
     '{"@context": "https://doi.org/10.5063/schema/codemeta-2.0", "@type": '
     '"SoftwareSourceCode", "name": "My Tool", "version": "1.0.0", "license": '
     '"https://spdx.org/licenses/MIT", "description": "A tool for parsing '
     'research dataset metadata."}', "file"),
    ("clean_web_manifest",
     '{"name": "My Progressive Web App", "short_name": "MyPWA", "start_url": '
     '"/", "display": "standalone", "background_color": "#ffffff", "icons": '
     '[{"src": "/icon-192.png", "sizes": "192x192", "type": "image/png"}]}',
     "file"),
    ("clean_dockerfile",
     'FROM python:3.12-slim\nWORKDIR /app\nCOPY requirements.txt .\n'
     'RUN pip install --no-cache-dir -r requirements.txt\nCOPY . .\n'
     'LABEL org.opencontainers.image.source="https://github.com/example/app"\n'
     'CMD ["python", "main.py"]', "file"),
    # ── Clean AI-agent CODE / DOCS — NORMAL ones. v0.2.68 BLOCKED ordinary
    #    AI-agent source (a LangChain agent, an MCP server, a prompt builder, an
    #    agent README) because generic words — agentic, assistants, llm agent,
    #    Claude, Codex, Copilot — were bare keywords on the agent-policy-poisoning
    #    patterns. Added Jun 27 2026 with the KEYWORD_DENYLIST generic-AI fix so
    #    the FP gate is no longer blind to the audience the product is FOR.
    ("clean_agent_code",
     '"""LangChain-style agent: an agentic LLM loop for an AI agent / assistant."""\n'
     'class Agent:\n'
     '    def __init__(self, model="claude", system_prompt="You are a helpful '
     'assistant."):\n'
     '        self.model, self.system_prompt = model, system_prompt\n'
     '        self.tools = []\n'
     '    def run(self, prompt):\n'
     '        return self.llm.invoke(prompt)', "file"),
    ("clean_mcp_server_code",
     '"""A normal MCP server exposing tools to an AI agent. Works with Claude, '
     'Codex, Copilot, GPT."""\n'
     'def list_tools():\n'
     '    return [{"name": "search", "description": "search the web for the '
     'assistant"}]\n'
     'def call_tool(name, args):\n'
     '    return {"ok": True}', "file"),
    ("clean_agent_readme",
     "# MyAgent\nAn open-source agentic framework for building autonomous AI "
     "agents and assistants. Supports Claude, Codex, and Copilot. The LLM agent "
     "can call tools, plan, and reflect. Configure the model and the system "
     "prompt; the AI assistant respects your instructions.", "file"),
    ("clean_prompt_builder",
     'SYSTEM = "You are Claude, an AI assistant. Be helpful, harmless, honest."\n'
     'def build(context, task):\n'
     '    return f"{SYSTEM}\\n{context}\\nTask: {task}"', "file"),
]


_STDLIB_DIR = os.path.dirname(json.__file__)


def clean_files():
    """Known-clean real files a reviewer points the tool at (stdlib json modules).
    Deliberately small/medium modules — large ones trigger slow regex backtracking
    (tracked separately). README excluded (contains attack-example strings by design)."""
    files = []
    for mod in ("decoder.py", "encoder.py"):
        cand = os.path.join(_STDLIB_DIR, mod)
        if os.path.exists(cand):
            files.append(cand)
    return files
