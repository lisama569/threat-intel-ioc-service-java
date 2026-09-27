package com.github.lisama569.threatinteliocservicejava.model;

import java.time.Instant;
import java.util.Locale;

/** 一条被拒收情报的留档，用于命中判定时与“未命中”区分。 */
public record RejectionRecord(
        String rawType,
        String rawValue,
        RejectReason reason,
        String detail,
        Instant rejectedAt) {

    /** key 统一小写，避免大小写差异导致查询不到留档。 */
    public String key() {
        return keyOf(rawType, rawValue);
    }

    public static String keyOf(String rawType, String rawValue) {
        return String.valueOf(rawType).toLowerCase(Locale.ROOT)
                + ":" + String.valueOf(rawValue).toLowerCase(Locale.ROOT);
    }
}
