import json
import os
from pathlib import Path
from typing import Any, Dict, List, Set


class PolicyEngine:
    """Simple rules-based moderation policy engine.

    Policy format (JSON):
    {
      "policy_version": "...",
      "rules": [
        {
          "id": "R-...",
          "description": "...",
          "conditions": { "risk_level": ["HIGH"], "stage": ["ISOLATION"] },
          "actions": ["ALERT_MOD"]
        }
      ]
    }
    """

    def __init__(self, policy_path: str | None = None):
        # Resolve default policy relative to this file so it works locally and on Render.
        base_dir = Path(__file__).resolve().parent
        default_policy_path = base_dir / "default_policy.json"

        # Priority:
        # 1. explicit argument
        # 2. env var
        # 3. local default next to this file
        env_path = os.getenv("PLAY_SENTINEL_POLICY_PATH")
        self.policy_path = Path(policy_path or env_path or default_policy_path)
        self.policy = self.load_policy()

    def load_policy(self) -> Dict[str, Any]:
        with open(self.policy_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError("Policy JSON must be an object")
        data.setdefault("rules", [])
        return data

    def evaluate(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate policy rules for a given context.

        Context typically contains:
          - risk_level: SAFE/LOW/MEDIUM/HIGH/CRITICAL
          - stage: LOW/TRUST_BUILDING/INFO_GATHERING/ISOLATION/GROOMING
        """
        triggered_actions: Set[str] = set()
        action_reasons: List[Dict[str, str]] = []

        for rule in self.policy.get("rules", []):
            if self._rule_matches(rule, context):
                for action in rule.get("actions", []):
                    triggered_actions.add(str(action))
                action_reasons.append({
                    "rule_id": str(rule.get("id", "")),
                    "description": str(rule.get("description", "")),
                })

        if not triggered_actions:
            triggered_actions.add("ALLOW")

        return {
            "actions": sorted(triggered_actions),
            "action_reasons": action_reasons,
            "policy_version": self.policy.get("policy_version", ""),
        }

    def _rule_matches(self, rule: Dict[str, Any], context: Dict[str, Any]) -> bool:
        conditions = rule.get("conditions", {})
        if not isinstance(conditions, dict):
            return False

        for field, expected_values in conditions.items():
            if not isinstance(expected_values, list):
                expected_values = [expected_values]
            if context.get(field) not in expected_values:
                return False
        return True
