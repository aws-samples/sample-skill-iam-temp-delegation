"""Pre-fetch SAR data for all actions referenced in a policy bundle.

Usage:
    python scripts/sar_prefetch.py <template_path> [<boundary_path>]

Extracts every service:action pair from the bundle's policy documents, looks
them up against the live AWS Service Authorization Reference feed, and writes
a JSON file with the results. This file is then available as grounded context
for the reviewer/verifier stages.

Output: writes to <template_dir>/sar_context.json

Each entry in the output maps an action to its SAR data:
{
  "iam:CreateRole": {
    "resource_types": ["role"],
    "condition_keys": ["iam:PermissionsBoundary", "aws:RequestTag/${TagKey}", ...],
    "properties": { "is_write": true, "is_permission_management": true, ... }
  },
  ...
}

Actions not found in the SAR are recorded with "not_found": true.
"""

import asyncio
import json
import re
import sys
from pathlib import Path

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.sar_lib import (
    LookupHit,
    ServiceReferenceClient,
    lookup,
    set_default_client,
)

# Pattern to extract "service:Action" from IAM policy Action values.
_ACTION_PATTERN = re.compile(
    r'^([a-zA-Z0-9\-]+):([a-zA-Z0-9\*]+)$'
)


def _extract_actions_from_statement(statement: dict) -> set[tuple[str, str]]:
    """Extract (service, action) pairs from a single IAM policy statement.

    Only looks at the "Action" or "NotAction" fields — never Condition blocks.
    """
    pairs: set[tuple[str, str]] = set()
    for key in ("Action", "NotAction"):
        actions = statement.get(key, [])
        if isinstance(actions, str):
            actions = [actions]
        for action_str in actions:
            match = _ACTION_PATTERN.match(action_str)
            if match:
                service = match.group(1).lower()
                action = match.group(2)
                # Skip wildcards — can't look up "Describe*" or "*"
                if "*" in action or "?" in action:
                    continue
                pairs.add((service, action))
    return pairs


def extract_actions_from_policy(text: str) -> set[tuple[str, str]]:
    """Extract (service, action) pairs from a parsed IAM policy document.

    Only extracts from Action/NotAction arrays in statements — ignores
    Condition blocks, Resource fields, and other locations where
    "service:Name" patterns appear as condition keys (not actions).

    Returns a set of (service, action_name) tuples. Wildcard actions like
    "ec2:*" or "ec2:Describe*" are skipped since they can't be looked up
    individually.
    """
    pairs: set[tuple[str, str]] = set()
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        return pairs

    statements = parsed.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]

    for stmt in statements:
        if isinstance(stmt, dict):
            pairs.update(_extract_actions_from_statement(stmt))

    return pairs


async def prefetch_sar_data(
    actions: set[tuple[str, str]],
) -> dict[str, dict]:
    """Look up each (service, action) pair against the live SAR feed.

    Returns a dict keyed by "service:action" with the SAR data or a not_found marker.
    """
    results: dict[str, dict] = {}

    for service, action in sorted(actions):
        key = f"{service}:{action}"
        try:
            result = await lookup(service, action)
            if isinstance(result, LookupHit):
                results[key] = {
                    "resource_types": result.row.resource_types,
                    "condition_keys": result.row.condition_keys,
                    "properties": {
                        "is_write": result.properties.is_write,
                        "is_list": result.properties.is_list,
                        "is_permission_management": result.properties.is_permission_management,
                        "is_tagging_only": result.properties.is_tagging_only,
                    },
                }
            else:
                results[key] = {"not_found": True}
        except Exception as exc:
            results[key] = {"error": str(exc)}

    return results


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python sar_prefetch.py <template_path> [<boundary_path>]")
        sys.exit(1)

    template_path = Path(sys.argv[1])
    boundary_path = Path(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].lower() != "none" else None

    # Collect raw text from all input files
    texts: list[str] = []
    texts.append(template_path.read_text())
    if boundary_path is not None:
        texts.append(boundary_path.read_text())

    # Extract all action references (only from Action/NotAction fields, not Condition blocks)
    all_actions: set[tuple[str, str]] = set()
    for text in texts:
        all_actions.update(extract_actions_from_policy(text))

    if not all_actions:
        print("No actions found in the bundle. Nothing to look up.")
        sys.exit(0)

    print(f"Found {len(all_actions)} unique actions to look up against SAR...")

    # Initialize the client and run lookups
    client = ServiceReferenceClient()
    set_default_client(client)

    results = asyncio.run(prefetch_sar_data(all_actions))

    # Write output
    output_path = template_path.parent / "sar_context.json"
    output_path.write_text(json.dumps(results, indent=2, sort_keys=True) + "\n")

    # Print summary
    found = sum(1 for v in results.values() if "not_found" not in v and "error" not in v)
    not_found = sum(1 for v in results.values() if v.get("not_found"))
    errors = sum(1 for v in results.values() if "error" in v)

    print(f"SAR lookup complete: {found} found, {not_found} not found, {errors} errors")
    print(f"Output written to: {output_path}")

    # Print a brief table for the agent's context
    print("\n--- SAR Summary ---")
    for action_key, data in sorted(results.items()):
        if data.get("not_found"):
            print(f"  {action_key}: [PERMISSION ONLY / NOT FOUND] — cannot be resource-scoped or condition-scoped")
        elif data.get("error"):
            print(f"  {action_key}: [ERROR] {data['error']}")
        else:
            resources = data["resource_types"] or ["(none — permission only)"]
            keys_count = len(data["condition_keys"])
            props = data["properties"]
            flags = []
            if props.get("is_write"):
                flags.append("WRITE")
            if props.get("is_permission_management"):
                flags.append("PERM-MGMT")
            if props.get("is_tagging_only"):
                flags.append("TAGGING")
            if props.get("is_list"):
                flags.append("LIST")
            flag_str = f" [{', '.join(flags)}]" if flags else ""
            print(f"  {action_key}: resources={resources}, {keys_count} condition keys{flag_str}")


if __name__ == "__main__":
    main()
