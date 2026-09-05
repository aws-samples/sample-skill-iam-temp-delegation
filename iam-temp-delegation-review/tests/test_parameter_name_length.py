"""Regression tests for delegation parameter-name length enforcement.

Covers FEATURE-template-parameter-minimum.md: the platform's
``CreateDelegationRequest`` API rejects any ``Permissions.Parameters[].Name``
shorter than 5 characters (``policyParameterNameType``: min 5, max 256). Both
``@{name}`` placeholders and ``@Enabled`` directive values become parameter
names, so the gate must catch short names (e.g. ``"@Enabled": "KMS"``) before
submission.

Stdlib ``unittest`` only — run with::

    python3 -m unittest discover -s tests
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.checks_lib import (  # noqa: E402
    PARAMETER_COUNT_LIMIT,
    PARAMETER_NAME_MAX_LENGTH,
    PARAMETER_NAME_MIN_LENGTH,
    gate,
    validate_parameters,
)
from iam_delegation_review.shared import Bundle, PolicyDoc  # noqa: E402


def _doc(policy: dict) -> PolicyDoc:
    raw = json.dumps(policy)
    return PolicyDoc(id="delegation_template.json", raw=raw, parsed=json.loads(raw))


# The exact failing shape from the feature report: @Enabled: "KMS" (3 chars).
_KMS_STATEMENT = {
    "@Enabled": "KMS",
    "Sid": "UseAwsManagedSecretsManagerKey",
    "Effect": "Allow",
    "Action": ["kms:GenerateDataKey", "kms:Decrypt"],
    "Resource": "*",
    "Condition": {"StringLike": {"kms:ViaService": "secretsmanager.*.amazonaws.com"}},
}


class ShortEnabledDirectiveTest(unittest.TestCase):
    def test_kms_directive_is_flagged_hard_fail(self) -> None:
        doc = _doc({"Version": "2012-10-17", "Statement": [_KMS_STATEMENT]})
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertEqual(len(result.findings), 1)
        msg = result.findings[0].message
        self.assertIn("'KMS'", msg)
        self.assertIn("@Enabled directive", msg)
        self.assertIn(str(PARAMETER_NAME_MIN_LENGTH), msg)

    def test_enabled_at_min_length_passes(self) -> None:
        # 5-char directive value is exactly at the minimum.
        stmt = dict(_KMS_STATEMENT, **{"@Enabled": "KMSKY"})
        doc = _doc({"Version": "2012-10-17", "Statement": [stmt]})
        result = validate_parameters(doc)
        self.assertFalse(result.hard_fail)
        self.assertEqual(result.findings, [])


class ShortPlaceholderTest(unittest.TestCase):
    def test_short_placeholder_is_flagged(self) -> None:
        doc = _doc({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "S0",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::@{b}/*"],  # @{b} -> name "b" (1 char)
            }],
        })
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertEqual(len(result.findings), 1)
        self.assertIn("'b'", result.findings[0].message)
        self.assertIn("@{b} placeholder", result.findings[0].message)

    def test_long_enough_placeholder_passes(self) -> None:
        doc = _doc({
            "Version": "2012-10-17",
            "Statement": [{
                "Sid": "S0",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::@{bucketName}/*"],
            }],
        })
        result = validate_parameters(doc)
        self.assertFalse(result.hard_fail)
        self.assertEqual(result.findings, [])


class BoundsAndDedupTest(unittest.TestCase):
    def test_too_long_name_is_flagged(self) -> None:
        long_name = "x" * (PARAMETER_NAME_MAX_LENGTH + 1)
        stmt = dict(_KMS_STATEMENT, **{"@Enabled": long_name})
        doc = _doc({"Version": "2012-10-17", "Statement": [stmt]})
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertIn(str(PARAMETER_NAME_MAX_LENGTH), result.findings[0].message)

    def test_duplicate_short_names_reported_once(self) -> None:
        doc = _doc({
            "Version": "2012-10-17",
            "Statement": [
                dict(_KMS_STATEMENT, Sid="A"),
                dict(_KMS_STATEMENT, Sid="B"),  # both @Enabled: "KMS"
            ],
        })
        result = validate_parameters(doc)
        self.assertEqual(len(result.findings), 1, "same short name reported once")


class NamePatternTest(unittest.TestCase):
    def test_control_char_in_enabled_value_is_flagged(self) -> None:
        # Tab inside the directive value -> outside [ -~].
        stmt = dict(_KMS_STATEMENT, **{"@Enabled": "KMS\tKEY"})
        doc = _doc({"Version": "2012-10-17", "Statement": [stmt]})
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertTrue(
            any("pattern" in f.message and "printable ASCII" in f.message
                for f in result.findings),
            "a control character must trigger the pattern finding",
        )

    def test_non_ascii_placeholder_name_is_flagged(self) -> None:
        # Build raw JSON that keeps the literal non-ASCII char (é, 0x00E9);
        # json.dumps default ensure_ascii=True would escape it to ASCII "\u00e9".
        raw = json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{
                    "Sid": "S0",
                    "Effect": "Allow",
                    "Action": ["s3:GetObject"],
                    "Resource": ["arn:aws:s3:::@{café-bucket}/*"],  # é is non-ASCII
                }],
            },
            ensure_ascii=False,
        )
        doc = PolicyDoc(id="delegation_template.json", raw=raw, parsed=json.loads(raw))
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertTrue(
            any("pattern" in f.message for f in result.findings),
            "a non-ASCII name must trigger the pattern finding",
        )

    def test_printable_ascii_with_space_passes(self) -> None:
        # Space (0x20) and punctuation are inside [ -~].
        stmt = dict(_KMS_STATEMENT, **{"@Enabled": "KMS Key_v2"})
        doc = _doc({"Version": "2012-10-17", "Statement": [stmt]})
        result = validate_parameters(doc)
        self.assertFalse(result.hard_fail)
        self.assertEqual(result.findings, [])

    def test_short_and_bad_pattern_reported_independently(self) -> None:
        # 3-char name AND contains a tab -> both length and pattern findings.
        stmt = dict(_KMS_STATEMENT, **{"@Enabled": "K\tY"})
        doc = _doc({"Version": "2012-10-17", "Statement": [stmt]})
        result = validate_parameters(doc)
        msgs = " ".join(f.message for f in result.findings)
        self.assertIn("at least", msgs)          # length finding
        self.assertIn("printable ASCII", msgs)   # pattern finding
        self.assertGreaterEqual(len(result.findings), 2)


class ParameterCountTest(unittest.TestCase):
    def _template_with_n_placeholders(self, n: int) -> PolicyDoc:
        # Each Resource uses a distinct, valid (>=5 char) placeholder name.
        statements = [
            {
                "Sid": f"S{i}",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": [f"arn:aws:s3:::@{{bucketName{i:03d}}}/*"],
            }
            for i in range(n)
        ]
        return _doc({"Version": "2012-10-17", "Statement": statements})

    def test_at_limit_passes(self) -> None:
        doc = self._template_with_n_placeholders(PARAMETER_COUNT_LIMIT)
        result = validate_parameters(doc)
        self.assertFalse(result.hard_fail)
        self.assertEqual(result.findings, [])

    def test_over_limit_is_flagged(self) -> None:
        doc = self._template_with_n_placeholders(PARAMETER_COUNT_LIMIT + 1)
        result = validate_parameters(doc)
        self.assertTrue(result.hard_fail)
        self.assertTrue(
            any("exceeding the delegation platform limit" in f.message
                for f in result.findings),
            "over-limit parameter count must be flagged",
        )

    def test_duplicate_names_do_not_inflate_count(self) -> None:
        # Same placeholder repeated many times = 1 distinct parameter.
        statements = [
            {
                "Sid": f"S{i}",
                "Effect": "Allow",
                "Action": ["s3:GetObject"],
                "Resource": ["arn:aws:s3:::@{bucketName}/*"],
            }
            for i in range(PARAMETER_COUNT_LIMIT + 10)
        ]
        doc = _doc({"Version": "2012-10-17", "Statement": statements})
        result = validate_parameters(doc)
        self.assertFalse(
            result.hard_fail,
            "repeated identical placeholders count as one distinct parameter",
        )


class GateIntegrationTest(unittest.TestCase):
    def test_gate_hard_fails_and_short_circuits_on_short_parameter(self) -> None:
        doc = _doc({"Version": "2012-10-17", "Statement": [_KMS_STATEMENT]})
        bundle = Bundle(partner_name="cisco", use_case="mdb", templates=[doc], boundary=None)
        result = gate(bundle, run_validate_policy=False)
        self.assertTrue(result.hard_fail)
        # Short-circuit: no rendered docs produced.
        self.assertEqual(result.rendered, [])
        self.assertTrue(
            any("KMS" in f.message and "Parameter name" in f.message for f in result.findings),
            "gate findings should include the short parameter-name error",
        )


if __name__ == "__main__":
    unittest.main()
