def calculate_metrics(results: list[dict]) -> dict:
    """
    Calculate binary classification metrics.

    Each result must contain:
        expected: True for attack, False for benign
        detected: True if the system detected an attack
    """

    true_positive = 0
    true_negative = 0
    false_positive = 0
    false_negative = 0

    for result in results:

        expected = result["expected"]
        detected = result["detected"]

        if expected is True and detected is True:
            true_positive += 1

        elif expected is False and detected is False:
            true_negative += 1

        elif expected is False and detected is True:
            false_positive += 1

        elif expected is True and detected is False:
            false_negative += 1

    total = (
        true_positive
        + true_negative
        + false_positive
        + false_negative
    )

    accuracy = (
        (true_positive + true_negative) / total
        if total
        else 0.0
    )

    precision = (
        true_positive / (true_positive + false_positive)
        if (true_positive + false_positive)
        else 0.0
    )

    recall = (
        true_positive / (true_positive + false_negative)
        if (true_positive + false_negative)
        else 0.0
    )

    f1_score = (
        2 * precision * recall / (precision + recall)
        if (precision + recall)
        else 0.0
    )

    detection_rate = recall

    false_positive_rate = (
        false_positive / (false_positive + true_negative)
        if (false_positive + true_negative)
        else 0.0
    )

    return {
        "total_samples": total,
        "true_positive": true_positive,
        "true_negative": true_negative,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1_score, 4),
        "detection_rate": round(detection_rate, 4),
        "false_positive_rate": round(
            false_positive_rate,
            4
        )
    }