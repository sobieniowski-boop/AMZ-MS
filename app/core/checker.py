from __future__ import annotations
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import yaml
from pathlib import Path

@dataclass
class MessageContext:
    marketplace: str = "DE"
    text: str = ""
    is_proactive: bool = False
    days_since_order_completion: int = 0
    order_id: Optional[str] = None

def load_rules(config_path: str) -> Dict[str, Any]:
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}

def check_message(ctx: MessageContext, rules: Dict[str, Any]) -> Dict[str, Any]:
    text = ctx.text or ""
    findings: List[Dict[str, Any]] = []
    scoring = rules.get("scoring", {})
    base = int(scoring.get("base", 100))
    penalties = scoring.get("penalties", {"BLOCK": 60, "REVIEW": 25})
    score = base
    verdict = "ALLOW"

    for rule in rules.get("rules", []):
        rid = rule.get("id", "RULE")
        severity = (rule.get("severity") or "REVIEW").upper()
        title = rule.get("title", rid)
        for pat in rule.get("patterns", []):
            if re.search(pat, text):
                findings.append({
                    "rule_id": rid,
                    "severity": severity,
                    "title": title,
                    "pattern": pat,
                })
                score -= int(penalties.get(severity, 10))
                break

    score = max(0, min(100, score))

    if any(f["severity"] == "BLOCK" for f in findings):
        verdict = "BLOCK"
    elif findings or (ctx.is_proactive and ctx.days_since_order_completion <= 3):
        verdict = "REVIEW"
    else:
        verdict = "ALLOW"

    # Simple explanations (safe)
    notes = []
    if ctx.is_proactive:
        notes.append("Proactive message: ensure timing and content comply with Amazon Communication Guidelines.")
    if ctx.order_id:
        notes.append("Order ID provided: good for context, avoid requesting reviews or off-platform contact.")

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "notes": notes,
        "marketplace": ctx.marketplace,
    }
