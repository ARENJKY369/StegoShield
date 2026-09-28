package analysis;

import java.util.Objects;

/**
 * One explainable scanner result, including the test that triggered, its score
 * contribution, and a human-readable reason.
 *
 * @param test short test name
 * @param points non-negative risk points contributed before score capping
 * @param reason concrete explanation of the observed evidence
 */
public record Finding(String test, int points, String reason) {
    /**
     * Validates a finding's fields.
     */
    public Finding {
        Objects.requireNonNull(test, "finding test must not be null");
        Objects.requireNonNull(reason, "finding reason must not be null");
        if (test.isBlank() || reason.isBlank()) {
            throw new IllegalArgumentException("finding test and reason must not be blank");
        }
        if (points < 0) {
            throw new IllegalArgumentException("finding points must not be negative");
        }
    }
}
