package com.github.lisama569.threatinteliocservicejava.ioc.aggregate;

import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizedIoc;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * 同一 IOC 的聚合体：按来源持有各条上报。
 * 读写分离锁保证并发上报/查询时不会出现计数丢失或脏读。
 */
public class IocAggregate {

    private final NormalizedIoc ioc;
    private final Map<String, ReportEntry> entriesBySource = new LinkedHashMap<>();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    public IocAggregate(NormalizedIoc ioc) {
        this.ioc = ioc;
    }

    public NormalizedIoc ioc() {
        return ioc;
    }

    /** 同一来源重复上报时覆盖旧记录（每个来源只保留最新一条）。 */
    public void upsert(ReportEntry entry) {
        lock.writeLock().lock();
        try {
            entriesBySource.put(entry.sourceId(), entry);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** 当前全部上报的一致性快照。 */
    public List<ReportEntry> snapshot() {
        lock.readLock().lock();
        try {
            return new ArrayList<>(entriesBySource.values());
        } finally {
            lock.readLock().unlock();
        }
    }
}
