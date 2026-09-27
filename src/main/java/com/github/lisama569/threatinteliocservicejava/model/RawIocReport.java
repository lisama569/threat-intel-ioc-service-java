package com.github.lisama569.threatinteliocservicejava.model;

import java.time.Instant;

/**
 * 外部来源上报的原始情报。所有字段可空，缺失字段在归一化阶段被识别并拒收。
 */
public record RawIocReport(
        String source,
        String type,
        String value,
        String verdict,
        Double confidence,
        Instant reportedAt,
        Long ttlSeconds) {
}
