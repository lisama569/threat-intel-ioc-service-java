package com.github.lisama569.threatinteliocservicejava.model;

import java.time.Instant;

/** 一次来源上报（ sightings ），记录判定、置信度与生命周期。 */
public record Sighting(
        String source,
        Verdict verdict,
        double confidence,
        Instant reportedAt,
        Instant expiresAt) {

    public boolean isExpired(Instant now) {
        return !now.isBefore(expiresAt);
    }
}
