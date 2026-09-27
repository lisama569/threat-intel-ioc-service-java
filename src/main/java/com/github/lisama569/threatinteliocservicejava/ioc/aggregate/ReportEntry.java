package com.github.lisama569.threatinteliocservicejava.ioc.aggregate;

import com.github.lisama569.threatinteliocservicejava.ioc.model.Verdict;

/**
 * 一条已受理的来源上报记录（不可变）。
 * sourceWeight 固化了上报时刻的来源权重，保证权重调整后历史判定可复现。
 */
public record ReportEntry(
        String sourceId,
        double sourceWeight,
        Verdict verdict,
        double confidence,
        long reportedAtEpochMs,
        long ttlSeconds) {

    /** 该上报是否在给定时刻已过期（到期即过期）。 */
    public boolean isExpiredAt(long nowEpochMs) {
        return nowEpochMs >= reportedAtEpochMs + ttlSeconds * 1000L;
    }

    /**
     * 按时间线性衰减后的有效置信度：
     * effective = confidence * sourceWeight * (1 - age/ttl)，过期时为 0。
     */
    public double effectiveConfidenceAt(long nowEpochMs) {
        if (isExpiredAt(nowEpochMs)) {
            return 0.0;
        }
        long ttlMs = ttlSeconds * 1000L;
        long ageMs = Math.max(0L, nowEpochMs - reportedAtEpochMs);
        double decay = 1.0 - (double) ageMs / (double) ttlMs;
        return confidence * sourceWeight * decay;
    }
}
