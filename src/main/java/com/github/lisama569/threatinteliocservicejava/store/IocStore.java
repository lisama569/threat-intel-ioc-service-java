package com.github.lisama569.threatinteliocservicejava.store;

import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.RejectionRecord;
import com.github.lisama569.threatinteliocservicejava.model.Sighting;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 线程安全的内存情报库。
 * 每个 IOC 一个条目，条目的增删改都在该条目的监视器锁内完成，
 * 返回的 {@link StoreEntryView} 是不可变快照，调用方不会读到更新一半的中间态。
 * 删除是逻辑删除（墓碑），以便命中判定时与“从未见过”区分。
 */
@Component
public class IocStore {

    private static final class Entry {
        final NormalizedIoc ioc;
        final List<Sighting> sightings = new ArrayList<>();
        boolean deleted;
        Instant updatedAt;

        Entry(NormalizedIoc ioc) {
            this.ioc = ioc;
        }

        StoreEntryView snapshot() {
            return new StoreEntryView(ioc, deleted, List.copyOf(sightings), updatedAt);
        }
    }

    private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, RejectionRecord> rejections = new ConcurrentHashMap<>();

    /** 原子地追加一次上报并返回更新后的快照；已删除条目被新上报复活。 */
    public StoreEntryView addSighting(NormalizedIoc ioc, Sighting sighting, Instant now) {
        Entry entry = entries.computeIfAbsent(ioc.key(), k -> new Entry(ioc));
        synchronized (entry) {
            entry.sightings.add(sighting);
            entry.deleted = false;
            entry.updatedAt = now;
            return entry.snapshot();
        }
    }

    /** 逻辑删除，保留墓碑以便与“未命中”区分。 */
    public Optional<StoreEntryView> delete(NormalizedIoc ioc, Instant now) {
        Entry entry = entries.get(ioc.key());
        if (entry == null) {
            return Optional.empty();
        }
        synchronized (entry) {
            if (entry.deleted) {
                return Optional.of(entry.snapshot());
            }
            entry.deleted = true;
            entry.updatedAt = now;
            return Optional.of(entry.snapshot());
        }
    }

    public Optional<StoreEntryView> find(NormalizedIoc ioc) {
        Entry entry = entries.get(ioc.key());
        if (entry == null) {
            return Optional.empty();
        }
        synchronized (entry) {
            return Optional.of(entry.snapshot());
        }
    }

    /** 留档一条被拒收的情报（按原始 type+value 索引）。 */
    public void recordRejection(RejectionRecord rejection) {
        rejections.put(rejection.key(), rejection);
    }

    public Optional<RejectionRecord> findRejection(String rawType, String rawValue) {
        return Optional.ofNullable(rejections.get(rawType + ":" + rawValue));
    }

    /** 当前条目数（测试与监控用）。 */
    public int size() {
        return entries.size();
    }
}
