"""
Problem 7 fix: numerical "confidence" values in this codebase (0.85, 0.92,
0.95, etc.) were never calibrated against labeled ground truth -- they are
just heuristic weights someone picked ("this rule feels pretty reliable").
Presenting that number to an analyst as "92% confidence" implies a
statistical guarantee ("this is right 92% of the time") that we cannot
actually back up.

We keep the raw float internally where it's genuinely useful -- e.g. for
sorting edges/campaigns by relative strength, or as a threshold in code --
but the ONLY thing ever shown to a person is a categorical label:

  Evidence Strength: STRONG / MODERATE / WEAK        (graph edges, findings)
  Relationship Strength: 86/100 (HIGH)                (campaign similarity)

The 0/100 number in "Relationship Strength" is not claimed to be a
probability either -- it's an explicit 0-100 heuristic scale, same idea as
a credit-score-style index rather than a percentage chance of anything.
"""


def evidence_strength_label(value: float) -> str:
    """Bucket a 0.0-1.0 internal weight into a defensible category label."""
    if value is None:
        return "UNKNOWN"
    if value >= 0.85:
        return "STRONG"
    elif value >= 0.65:
        return "MODERATE"
    return "WEAK"


def relationship_strength_label(value: float) -> str:
    """Format a 0.0-1.0 internal weight as an explicit 0-100 scale + label."""
    if value is None:
        return "0/100 (UNKNOWN)"
    score = int(round(max(0.0, min(1.0, value)) * 100))
    return f"{score}/100 ({evidence_strength_label(value)})"
