package com.github.lisama569.threatinteliocservicejava.ioc.aggregate;

import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizedIoc;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 并发安全的 IOC 聚合存储。
 * 写操作（上报/删除）在 store 级别串行化，避免删除与上报交错导致状态只更新一半；
 * 删除留下墓碑，使判定结果能区分"已删除"与"未命中"。
 */
@Component
public class IocStore {

    private final Map<NormalizedIoc, IocAggregate> aggregates = new ConcurrentHashMap<>();
    private final Set<NormalizedIoc> tombstones = ConcurrentHashMap.newKeySet();

    /** 原子地上报一条记录：创建/更新聚合体并清除墓碑。 */
    public synchronized IocAggregate upsertEntry(NormalizedIoc ioc, ReportEntry entry) {
        IocAggregate agg = aggregates.computeIfAbsent(ioc, IocAggregate::new);
        agg.upsert(entry);
        tombstones.remove(ioc);
        return agg;
    }

    public Optional<IocAggregate> find(NormalizedIoc ioc) {
        return Optional.ofNullable(aggregates.get(ioc));
    }

    /** 删除并留下墓碑；返回是否存在过。 */
    public synchronized boolean remove(NormalizedIoc ioc) {
        boolean existed = aggregates.remove(ioc) != null;
        if (existed) {
            tombstones.add(ioc);
        }
        return existed;
    }

    public boolean isDeleted(NormalizedIoc ioc) {
        return tombstones.contains(ioc);
    }
}
