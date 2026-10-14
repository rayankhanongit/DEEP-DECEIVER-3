def calculate_risk_score(
    fast_filter_score: float,
    sentry_score: float,
    indirect_score: float = 0.0
) -> float:
    """
    Calculate the combined threat risk score.

    Fast Filter and Sentry retain their original weights.
    Indirect injection detection provides an additional
    confidence signal when contextual injection is detected.
    """

    # Original risk model.
    base_risk = (
        0.30 * fast_filter_score
        + 0.70 * sentry_score
    )

    # Indirect injection is an additional high-confidence signal.
    if indirect_score > 0:
        indirect_bonus = 0.50 * indirect_score
    else:
        indirect_bonus = 0.0

    risk = base_risk + indirect_bonus

    return round(
        min(1.0, max(0.0, risk)),
        4
    )