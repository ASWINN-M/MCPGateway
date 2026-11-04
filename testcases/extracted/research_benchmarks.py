"""
Research landscape for agent / MCP security, with published ASR figures.

Numbers are taken from public paper / leaderboard pages (AgentDojo, InjecAgent)
and related MCP security work. This is a *metric-family* comparison (targeted ASR),
not a claim that suites are identical.
"""

from __future__ import annotations


def research_landscape(our_asr_before: float, our_asr_after: float) -> dict:
    """Return privacy-safe research comparison payload for the trial UI."""
    peers = [
        {
            "id": "agentdojo-gpt4o-none",
            "family": "AgentDojo",
            "label": "AgentDojo GPT-4o (no defense)",
            "asr_pct": 47.69,
            "suite_size": 629,
            "defense": "None",
            "attack": "important_instructions",
            "source": "Debenedetti et al., AgentDojo (NeurIPS 2024 D&B)",
            "url": "https://arxiv.org/abs/2406.13352",
            "tone": "high",
        },
        {
            "id": "agentdojo-gpt4o-toolfilter",
            "family": "AgentDojo",
            "label": "AgentDojo GPT-4o + tool_filter",
            "asr_pct": 6.84,
            "suite_size": 629,
            "defense": "tool_filter",
            "attack": "important_instructions",
            "source": "AgentDojo public results (spylab.ai)",
            "url": "https://agentdojo.spylab.ai/results/",
            "tone": "low",
        },
        {
            "id": "agentdojo-gpt4o-pidetector",
            "family": "AgentDojo",
            "label": "AgentDojo GPT-4o + PI detector",
            "asr_pct": 7.95,
            "suite_size": 629,
            "defense": "transformers_pi_detector",
            "attack": "important_instructions",
            "source": "AgentDojo public results (spylab.ai)",
            "url": "https://agentdojo.spylab.ai/results/",
            "tone": "low",
        },
        {
            "id": "agentdojo-claude37-none",
            "family": "AgentDojo",
            "label": "AgentDojo Claude 3.7 Sonnet (no defense)",
            "asr_pct": 7.31,
            "suite_size": 629,
            "defense": "None",
            "attack": "important_instructions",
            "source": "AgentDojo public results (2025-02-24)",
            "url": "https://agentdojo.spylab.ai/results/",
            "tone": "low",
        },
        {
            "id": "injecagent-gpt4-react",
            "family": "InjecAgent",
            "label": "InjecAgent ReAct GPT-4 (base)",
            "asr_pct": 24.0,
            "suite_size": 1054,
            "defense": "None (prompted ReAct)",
            "attack": "indirect prompt injection",
            "source": "Zhan et al., InjecAgent (arXiv:2403.02691)",
            "url": "https://arxiv.org/abs/2403.02691",
            "tone": "mid",
        },
        {
            "id": "injecagent-gpt4-enhanced",
            "family": "InjecAgent",
            "label": "InjecAgent ReAct GPT-4 (enhanced)",
            "asr_pct": 47.0,
            "suite_size": 1054,
            "defense": "None + hacking prompt",
            "attack": "enhanced IPI",
            "source": "Zhan et al., InjecAgent (arXiv:2403.02691)",
            "url": "https://arxiv.org/abs/2403.02691",
            "tone": "high",
        },
        {
            "id": "injecagent-gpt4-finetuned",
            "family": "InjecAgent",
            "label": "InjecAgent fine-tuned GPT-4",
            "asr_pct": 7.1,
            "suite_size": 1054,
            "defense": "Fine-tuned tool-calling model",
            "attack": "IPI (base)",
            "source": "Zhan et al., InjecAgent (arXiv:2403.02691)",
            "url": "https://arxiv.org/abs/2403.02691",
            "tone": "low",
        },
        {
            "id": "ours-before",
            "family": "This project",
            "label": "This project BEFORE gateway",
            "asr_pct": float(our_asr_before),
            "suite_size": 16,
            "defense": "None (undefended mock agent)",
            "attack": "16 mail/calendar MCP cases",
            "source": "results/before_gateway.json",
            "url": "",
            "tone": "high",
            "is_ours": True,
        },
        {
            "id": "ours-after",
            "family": "This project",
            "label": "This project AFTER 3-phase gateway",
            "asr_pct": float(our_asr_after),
            "suite_size": 16,
            "defense": "Phase 1+2+3 MCP gateway",
            "attack": "16 mail/calendar MCP cases",
            "source": "results/after_gateway.json",
            "url": "",
            "tone": "low",
            "is_ours": True,
        },
    ]

    papers = [
        {
            "title": "AgentDojo: Evaluate Prompt Injection Attacks and Defenses for LLM Agents",
            "authors": "Debenedetti et al.",
            "year": 2024,
            "venue": "NeurIPS Datasets & Benchmarks",
            "arxiv": "2406.13352",
            "url": "https://arxiv.org/abs/2406.13352",
            "why": "Defines targeted ASR + utility under attack for tool-using agents; includes email-style tasks and Important Instructions attacks.",
            "overlap": "Same metric family (targeted ASR). Our TC-16 mirrors the Important Instructions style.",
        },
        {
            "title": "InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated LLM Agents",
            "authors": "Zhan et al.",
            "year": 2024,
            "venue": "arXiv",
            "arxiv": "2403.02691",
            "url": "https://arxiv.org/abs/2403.02691",
            "why": "1,054 IPI cases spanning direct harm and data-exfiltration via tools.",
            "overlap": "Same failure mode (tool misuse after injected content). Our suite is smaller and MCP/Gmail focused.",
        },
        {
            "title": "Securing MCP-based Agent Workflows (SAMOS)",
            "authors": "Ntousakis et al.",
            "year": 2025,
            "venue": "PACMI workshop / preprint",
            "arxiv": "",
            "url": "https://www.ntousakis.com/pacmi-25.pdf",
            "why": "MCP gateway that intercepts tool calls and enforces information-flow policies.",
            "overlap": "Same architecture idea as our Phase 2 central gateway (intercept before side effects).",
        },
        {
            "title": "AgentBound: Securing Execution Boundaries of AI Agents",
            "authors": "AgentBound authors",
            "year": 2025,
            "venue": "ACM (DOI 10.1145/3808103)",
            "arxiv": "",
            "url": "https://doi.org/10.1145/3808103",
            "why": "Least-privilege manifests + enforcement box around MCP servers.",
            "overlap": "Matches our Phase 1 least-privilege exposure + Phase 2 enforcement boundary.",
        },
        {
            "title": "ETDI: Mitigating Tool Squatting and Rug Pull Attacks in MCP",
            "authors": "ETDI authors",
            "year": 2025,
            "venue": "CARS 2025",
            "arxiv": "",
            "url": "https://doi.org/10.1109/cars67163.2025.11337310",
            "why": "Signed/versioned tool definitions and policy checks against squatting.",
            "overlap": "Related to our fixed allowlist rejecting squatted tools (TC-06 / TC-12).",
        },
        {
            "title": "Securing the Model Context Protocol (MCP): Risks, Controls, and Governance",
            "authors": "Survey / position paper",
            "year": 2025,
            "venue": "arXiv",
            "arxiv": "2511.20920",
            "url": "https://arxiv.org/abs/2511.20920",
            "why": "Catalogs MCP over-permissioning, dynamic tool discovery risks, and allowlist controls.",
            "overlap": "Motivates our department tool allowlists and deny-by-default stance.",
        },
        {
            "title": "MCP Security Gateway 1.0 (Agent Governance Toolkit)",
            "authors": "Microsoft Agent Governance Toolkit",
            "year": 2025,
            "venue": "Specification",
            "arxiv": "",
            "url": "https://microsoft.github.io/agent-governance-toolkit/specs/MCP-SECURITY-GATEWAY-1.0/",
            "why": "Deny-list, allow-list, sensitive-tool approval, then allow.",
            "overlap": "Maps closely to our Phase 1 allowlist + Phase 2 high-risk confirm / execution token.",
        },
    ]

    safety_measures = [
        {
            "measure": "Department least-privilege tool exposure",
            "phase": "Phase 1",
            "type": "Preventive (guidance)",
            "research_analogue": "AgentDojo tool_filter; AgentBound manifests; MCP Gateway allowlists",
            "what_we_do": "Trusted directory + policy.json expose only department-permitted tools.",
            "covers": ["TC-03", "TC-06", "TC-09", "TC-11", "TC-12"],
        },
        {
            "measure": "Independent pre-execution allow/deny",
            "phase": "Phase 2",
            "type": "Preventive (enforcement)",
            "research_analogue": "SAMOS MCP gateway; Microsoft MCP Security Gateway evaluation order",
            "what_we_do": "Re-check tool + args against policy before any Gmail/Calendar/stub side effect.",
            "covers": ["All tool requests"],
        },
        {
            "measure": "Caller authentication (local MCP client)",
            "phase": "Phase 2",
            "type": "Preventive (identity)",
            "research_analogue": "MCP governance / OAuth-enhanced tool identity (ETDI)",
            "what_we_do": "Reject unauthenticated local callers; OAuth alone is not client auth.",
            "covers": ["TC-05"],
        },
        {
            "measure": "Human approval + bound execution tokens",
            "phase": "Phase 2",
            "type": "Preventive (high-risk)",
            "research_analogue": "MCP Security Gateway sensitive_tools + approval_callback",
            "what_we_do": "send_email / calendar writes need human-approved execution token bound to args.",
            "covers": ["TC-01", "TC-07", "TC-08", "TC-13", "TC-14", "TC-15", "TC-16"],
        },
        {
            "measure": "Literal attachment / sandbox handling",
            "phase": "Phase 2",
            "type": "Preventive (data integrity)",
            "research_analogue": "AgentDojo attachment/data confusion cases; MCP risk catalogs",
            "what_we_do": "Filenames are literals; path traversal stays inside the attachments sandbox.",
            "covers": ["TC-02", "TC-10"],
        },
        {
            "measure": "Fixed tool allowlist (anti-squatting)",
            "phase": "Phase 1 + 2",
            "type": "Preventive",
            "research_analogue": "ETDI tool squatting / rug-pull defenses",
            "what_we_do": "Tools are fixed in the gateway; lookalike registration is rejected.",
            "covers": ["TC-06", "TC-12"],
        },
        {
            "measure": "Audit log + repeated-deny anomaly alerts",
            "phase": "Phase 3",
            "type": "Detective",
            "research_analogue": "SAMOS session monitoring; governance audit recommendations",
            "what_we_do": "Log every allow/deny; alert on repeated unauthorized attempts.",
            "covers": ["All decisions (does not block alone)"],
        },
    ]

    chart_rows = [
        {
            "label": p["label"],
            "sub": f"{p['family']} · suite ~{p['suite_size']} · {p['defense']}",
            "value": p["asr_pct"],
            "tone": p.get("tone") or "mid",
            "is_ours": bool(p.get("is_ours")),
            "family": p["family"],
        }
        for p in peers
    ]

    return {
        "title": "Research benchmarks vs this project",
        "caveat": (
            "Same metric family (targeted Attack Success Rate; lower is better), "
            "but suites differ in size, tasks, models, and attacks. "
            "Do not treat numbers as a strict leaderboard ranking."
        ),
        "metric_note": (
            "AgentDojo reports targeted ASR over ~629 security cases; "
            "InjecAgent over 1,054 IPI cases; this project uses 16 MCP mail/calendar cases."
        ),
        "papers": papers,
        "peers": peers,
        "chart": chart_rows,
        "safety_measures": safety_measures,
        "takeaways": [
            "Undefended capable agents still show double-digit ASR on AgentDojo / InjecAgent.",
            "Prompt-only or detector defenses help (AgentDojo tool_filter ~6.8% ASR) but leave residual risk.",
            "Our gateway targets residual risk with code enforcement (allowlist + confirm + tokens), not prompt trust.",
            "Phase 3 monitoring is detective; Phase 2 remains the hard security boundary.",
        ],
    }
