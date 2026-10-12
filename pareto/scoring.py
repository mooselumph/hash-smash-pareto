"""Explicit successor projection of authenticated, reviewed resource bounds.

This module neither authenticates evidence nor changes qualification. Call it
only after the original pipeline has verified the score. The original root
scorer remains time-only. See scoring-policies/README.md for source attribution.
"""
import math
from collections.abc import Mapping
from pathlib import Path

from scripts.scalar_scoring_policy import (
    SCORE_METRIC, active_scalar_policy, scalar_score, scoring_policy_metadata,
)
from verifier.errors import VerificationError
from verifier.io import canonical_json_bytes, load_json_bytes, sha256_bytes

ROOT = Path(__file__).resolve().parents[1]
ORCHARD_POLICY_ID = "hashsmash-orchard-tm-v1"
ORCHARD_POLICY_SHA256 = "497b0e3c33b57ab31fa79c957c22290327c50238793754184d48c93a86e363d7"
ORCHARD_POLICY_PATH = ROOT / "pareto/scoring-policies" / f"{ORCHARD_POLICY_ID}.json"


def objectives():
    return [{"name": "rounds", "direction": "+"},
            {"name": SCORE_METRIC, "direction": "-"}]


def policy_definition(family):
    if family in ("sha256", "sha3-256", "blake3"):
        return active_scalar_policy()
    if family != "poseidon":
        raise VerificationError("unknown normalized Pareto family")
    definition = load_json_bytes(ORCHARD_POLICY_PATH.read_bytes(), str(ORCHARD_POLICY_PATH))
    # Separate pinned identity: never weaken the approved v5 helper's guard or
    # relabel Orchard resources to pass it. Hash covers integer spelling as well.
    if (not isinstance(definition, dict) or definition.get("id") != ORCHARD_POLICY_ID
            or sha256_bytes(canonical_json_bytes(definition)) != ORCHARD_POLICY_SHA256):
        raise VerificationError("Orchard policy does not match its pinned ID and definition hash")
    return definition


def scoring_metadata(family):
    definition = policy_definition(family)
    if family != "poseidon":
        return scoring_policy_metadata(definition)
    return {"scoreMetric": SCORE_METRIC, "scoringPolicyId": ORCHARD_POLICY_ID,
            "scoringPolicySha256": ORCHARD_POLICY_SHA256}


def evaluation_policies(family):
    """The exact policy JSON Yukon transports, including ordered objectives.

    Yukon sends policies/fields/admission, not a top-level objectives field.
    This is metadata inside its existing arbitrary-JSON scoring policy.
    """
    definition = policy_definition(family)
    marker = scoring_metadata(family)
    return {
        "scoring": {
            "id": marker["scoringPolicyId"],
            "definitionSha256": marker["scoringPolicySha256"],
            "scoreMetric": marker["scoreMetric"],
            "sourceCostModelId": definition["sourceCostModelId"],
            "timeUnit": definition["timeUnit"],
            "objectives": objectives(),
        },
        "validity": {"id": "paired-lanes-v1", "lane": "exploratory"},
    }


def normalized_score(family, metrics):
    definition = policy_definition(family)
    if family != "poseidon":
        return scalar_score(metrics, definition)
    if not isinstance(metrics, Mapping):
        raise VerificationError("official Orchard score metrics must be an object")
    if metrics.get("costModelId") != definition["sourceCostModelId"]:
        raise VerificationError("official Orchard score metrics require orchard-field-ram-v2")
    if metrics.get("timeUnit") != definition["timeUnit"]:
        raise VerificationError("official Orchard score metrics require target-compressions")
    values = []
    for name in ("timeLog2", "memoryLog2Bytes"):
        value = metrics.get(name)
        try:
            valid = type(value) in (int, float) and math.isfinite(value) and value >= 0
        except OverflowError:
            valid = False
        if not valid:
            raise VerificationError(f"official Orchard score metrics.{name} must be a finite nonnegative number")
        values.append(float(value))
    # Same approved log-space arithmetic, applied to the distinct Orchard model.
    score = values[0] + max(0.0, values[1] - math.log2(definition["memoryUnitBytes"]))
    if not math.isfinite(score):
        raise VerificationError("Orchard policy result must be finite")
    return score
