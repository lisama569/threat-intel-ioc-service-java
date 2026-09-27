package com.github.lisama569.threatinteliocservicejava.ioc.model;

/** 拒收原因，要求可区分。 */
public enum RejectReason {
    MISSING_FIELD,
    UNKNOWN_TYPE,
    UNKNOWN_SOURCE,
    INVALID_DOMAIN,
    INVALID_IP,
    INVALID_URL,
    INVALID_HASH,
    INVALID_CONFIDENCE,
    INVALID_TTL
}
