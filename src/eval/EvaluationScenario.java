package eval;

/**
 * Runtime-generated evaluation categories. CLEAN is the negative control used
 * for false-positive measurement; every other category is a positive case.
 */
public enum EvaluationScenario {
    /** Original clean-image baseline. */
    CLEAN(false, "Clean baseline"),
    /** Sequential LSB payload occupying approximately ten percent of capacity. */
    LSB_10_PERCENT(true, "Sequential LSB at 10% capacity"),
    /** Sequential LSB payload occupying approximately twenty-five percent. */
    LSB_25_PERCENT(true, "Sequential LSB at 25% capacity"),
    /** Sequential LSB payload occupying approximately fifty percent. */
    LSB_50_PERCENT(true, "Sequential LSB at 50% capacity"),
    /** Sequential LSB payload occupying all available capacity. */
    LSB_100_PERCENT(true, "Sequential LSB at 100% capacity"),
    /** Bytes appended after the PNG IEND chunk. */
    PNG_APPENDED_DATA(true, "PNG appended data"),
    /** PNG bytes deliberately written under a non-image extension. */
    WRONG_EXTENSION(true, "Wrong extension");

    private final boolean positiveCase;
    private final String displayName;

    EvaluationScenario(boolean positiveCase, String displayName) {
        this.positiveCase = positiveCase;
        this.displayName = displayName;
    }

    /** @return whether scanner flagging counts toward detection rate */
    public boolean positiveCase() {
        return positiveCase;
    }

    /** @return user-facing scenario name */
    public String displayName() {
        return displayName;
    }

    /**
     * Returns the user-facing scenario name for an embedding placement mode.
     *
     * @param scattered whether LSB payloads were placed password-scattered
     * @return user-facing scenario name
     */
    public String displayName(boolean scattered) {
        if (!scattered) {
            return displayName;
        }
        return switch (this) {
            case LSB_10_PERCENT -> "Scattered LSB at 10% capacity";
            case LSB_25_PERCENT -> "Scattered LSB at 25% capacity";
            case LSB_50_PERCENT -> "Scattered LSB at 50% capacity";
            case LSB_100_PERCENT -> "Scattered LSB at 100% capacity";
            default -> displayName;
        };
    }
}
