"""Create a validated bundle_metadata.json file.

Usage:
    python scripts/create_metadata.py <output_dir> <partner_domain> <template_name> <template_description> [<boundary_name> <boundary_description>]

Auto-appends today's date as a _YYYY_MM_DD suffix to template_name and
boundary_name if not already present. Validates against the schema before writing.
"""

import json
import sys
from pathlib import Path

# Add the skill-local source to the path
_SKILL_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_SKILL_ROOT / "src"))

from iam_delegation_review.shared.metadata import (
    MetadataValidationError,
    ensure_date_suffix,
    validate_metadata,
)


def main() -> None:
    if len(sys.argv) < 5:
        print(
            "Usage: python create_metadata.py <output_dir> <partner_domain> "
            "<template_name> <template_description> "
            "[<boundary_name> <boundary_description>]"
        )
        sys.exit(1)

    output_dir = Path(sys.argv[1])
    partner_domain = sys.argv[2]
    template_name = sys.argv[3]
    template_description = sys.argv[4]
    boundary_name = sys.argv[5] if len(sys.argv) > 5 else None
    boundary_description = sys.argv[6] if len(sys.argv) > 6 else None

    # Auto-append date suffix.
    template_name = ensure_date_suffix(template_name)
    if boundary_name:
        boundary_name = ensure_date_suffix(boundary_name)

    # Build metadata object.
    metadata: dict = {
        "partner_domain": partner_domain,
        "template_name": template_name,
        "template_description": template_description,
    }
    if boundary_name:
        metadata["boundary_name"] = boundary_name
    if boundary_description:
        metadata["boundary_description"] = boundary_description

    # Validate against schema.
    try:
        validate_metadata(metadata)
    except MetadataValidationError as e:
        print(f"Error: {e}")
        sys.exit(1)

    # Write file.
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = output_dir / "bundle_metadata.json"
    output_path.write_text(json.dumps(metadata, indent=2) + "\n")

    print(f"✅ Metadata created: {output_path}")
    print(f"   partner_domain: {partner_domain}")
    print(f"   template_name: {template_name}")
    print(f"   template_description: {template_description}")
    if boundary_name:
        print(f"   boundary_name: {boundary_name}")
        print(f"   boundary_arn: arn:aws:iam::partner:policy/permission_boundary/{partner_domain}/{boundary_name}")
    if boundary_description:
        print(f"   boundary_description: {boundary_description}")


if __name__ == "__main__":
    main()
