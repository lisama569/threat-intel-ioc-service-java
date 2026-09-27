package com.github.lisama569.threatinteliocservicejava.store;

import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.Sighting;
import java.time.Instant;
import java.util.List;

/** 存储条目的一致性快照（在条目条目的锁内生成）。 */
public record StoreEntryView(
        NormalizedIoc ioc,
        boolean deleted,
        List<Sighting> sightings,
        Instant updatedAt) {
}
