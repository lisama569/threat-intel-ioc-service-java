package com.github.lisama569.threatinteliocservicejava.model;

import java.time.Instant;
import java.util.List;

/** 单个 IOC 的聚合视图（不可变快照，由 store 内部状态生成）。 */
public record IocRecord(
        NormalizedIoc ioc,
        IocStatus status,
        List<Sighting> sightings,
        Verdict verdict,
        double confidence,
        Instant updatedAt) {

    public int sightingCount() {
        return sightings.size();
    }
}
