"""Regression tests for @Enabled directive handling (Option B).

Covers the bug where the size gate measured the ``@``-stripped form while the
stored artifact retained ``@Enabled`` (BUG-template-size-artifact-mismatch.md).

The fix (Option B) keeps the authored form — including ``@Enabled`` — as the
stored artifact and on ``PolicyDoc.raw``, and strips ``@``-directives in the
render path so every rendered-form measurement (size limit, ARN structure,
Access Analyzer) is consistent.

These tests use only the standard library so they run with::

    python3 -m unittest discover -s tests

from the ``iam-temp-delegation-review`` directory (no pytest required).
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

# Add the skill-local source to the path (mirrors run_checks.py).
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.checks_lib import (  # noqa: E402
    TEMPLATE_SIZE_LIMIT,
    compute_size_risk,
    render_doc,
    strip_directives,
    validate_template_size,
)
from iam_delegation_review.shared import PolicyDoc  # noqa: E402


# An authored template with @Enabled on multiple statements. Pretty-printed so
# the authored artifact is a realistic on-disk form (indentation is irrelevant
# to the rendered/minified measurement).
_AUTHORED_TEMPLATE = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "@Enabled": "CLEANUP",
                "Sid": "CleanupOne",
                "Effect": "Allow",
                "Action": ["s3:DeleteObject"],
                "Resource": ["arn:aws:s3:::example-bucket-one/*"],
            },
            {
                "@Enabled": "CLEANUP",
                "Sid": "CleanupTwo",
                "Effect": "Allow",
                "Action": ["s3:DeleteObject"],
                "Resource": ["arn:aws:s3:::example-bucket-two/*"],
            },
            {
                "Sid": "AlwaysOn",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::example-bucket-one/*"],
            },
        ],
    },
    indent=2,
)


def _authored_doc() -> PolicyDoc:
    return PolicyDoc(
        id="delegation_template.json",
        raw=_AUTHORED_TEMPLATE,
        parsed=json.loads(_AUTHORED_TEMPLATE),
    )


def _minify(parsed: object) -> int:
    return len(json.dumps(parsed, separators=(",", ":")))


class StripDirectivesTest(unittest.TestCase):
    def test_removes_at_prefixed_statement_keys(self) -> None:
        parsed = json.loads(_AUTHORED_TEMPLATE)
        stripped = strip_directives(parsed)
        for stmt in stripped["Statement"]:
            self.assertFalse(
                [k for k in stmt if k.startswith("@")],
                "no @-prefixed keys should remain in the rendered form",
            )

    def test_does_not_mutate_input(self) -> None:
        parsed = json.loads(_AUTHORED_TEMPLATE)
        strip_directives(parsed)
        at_keys = [
            k
            for stmt in parsed["Statement"]
            if isinstance(stmt, dict)
            for k in stmt
            if k.startswith("@")
        ]
        self.assertEqual(len(at_keys), 2, "authored input must be left intact")


class RenderDocDropsDirectivesTest(unittest.TestCase):
    def test_rendered_doc_has_no_directives(self) -> None:
        for mode in ("nominal", "worst-case"):
            with self.subTest(mode=mode):
                rendered = render_doc(_authored_doc(), mode)
                self.assertIsNotNone(rendered.parsed)
                for stmt in rendered.parsed["Statement"]:
                    self.assertFalse(
                        [k for k in stmt if k.startswith("@")],
                        f"rendered ({mode}) form must be directive-free",
                    )
                # raw and parsed agree for the rendered doc.
                self.assertEqual(rendered.parsed, json.loads(rendered.raw))


class SizeMeasuredOnRenderedFormTest(unittest.TestCase):
    """The heart of the bug: gate size == stripped size, and the authored
    artifact over-counts by exactly the stripped directive bytes."""

    def test_gate_size_equals_stripped_size(self) -> None:
        doc = _authored_doc()
        stripped_size = _minify(strip_directives(doc.parsed))
        authored_size = _minify(doc.parsed)

        # The authored artifact (as stored) is larger than the rendered form.
        self.assertGreater(authored_size, stripped_size)

        # Two `"@Enabled":"CLEANUP",` fragments = 2 * 21 = 42 chars.
        self.assertEqual(authored_size - stripped_size, 42)

    def test_size_risk_finding_reports_stripped_size(self) -> None:
        doc = _authored_doc()
        stripped_size = _minify(strip_directives(doc.parsed))
        result = compute_size_risk(doc)
        self.assertEqual(len(result.findings), 1)
        message = result.findings[0].message
        # The gate reports the rendered-form size, not the authored size.
        self.assertIn(f"minified size is {stripped_size} characters", message)
        self.assertIn("rendered form", message)

    def test_stored_artifact_remeasures_to_gate_size_after_stripping(self) -> None:
        """A downstream consumer that reads the stored artifact (authored form)
        reproduces the gate's number by stripping directives — proving the
        stored bytes and the gated measurement are reconciled by the same
        canonical transform."""
        doc = _authored_doc()
        # Gate-reported size (from the finding, parsed back out).
        result = compute_size_risk(doc)
        message = result.findings[0].message
        # Extract the integer after "minified size is ".
        marker = "minified size is "
        start = message.index(marker) + len(marker)
        gate_size = int(message[start:].split(" ", 1)[0])

        # Re-measure the *stored artifact* (authored form, verbatim) the way a
        # reviewer would, then apply the canonical strip.
        stored_parsed = json.loads(doc.raw)  # doc.raw == stored artifact bytes
        remeasured = _minify(strip_directives(stored_parsed))
        self.assertEqual(remeasured, gate_size)

    def test_template_under_limit_passes(self) -> None:
        doc = _authored_doc()
        result = validate_template_size(doc)
        self.assertFalse(result.hard_fail)
        self.assertEqual(result.findings, [])

    def test_directives_can_decide_over_vs_under_limit(self) -> None:
        """A template whose authored form is over the limit but whose rendered
        form is under must PASS — the gate measures the rendered form."""
        # Build a policy whose rendered (stripped) minified size is <= limit,
        # then pad it with @-directive bytes so the authored form exceeds it.
        base = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "S0",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::b/*"],
                }
            ],
        }
        rendered_size = _minify(base)
        self.assertLessEqual(rendered_size, TEMPLATE_SIZE_LIMIT)

        # Add a large @-directive value so the authored form is well over 2048.
        padding = "X" * (TEMPLATE_SIZE_LIMIT + 100)
        base["Statement"][0]["@Enabled"] = padding
        authored = json.dumps(base, separators=(",", ":"))
        self.assertGreater(len(authored), TEMPLATE_SIZE_LIMIT)

        doc = PolicyDoc(id="t.json", raw=authored, parsed=json.loads(authored))
        result = validate_template_size(doc)
        self.assertFalse(
            result.hard_fail,
            "authored form is over-limit but rendered form is under — must pass",
        )


if __name__ == "__main__":
    unittest.main()
