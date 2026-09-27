package com.github.lisama569.threatinteliocservicejava.model;

/** 情报拒收原因，彼此可区分。 */
public enum RejectReason {
    MISSING_SOURCE,
    MISSING_TYPE,
    MISSING_VALUE,
    MISSING_VERDICT,
    UNKNOWN_TYPE,
    UNKNOWN_VERDICT,
    INVALID_VALUE_FORMAT,
    INVALID_CONFIDENCE,
    INVALID_TTL
}
