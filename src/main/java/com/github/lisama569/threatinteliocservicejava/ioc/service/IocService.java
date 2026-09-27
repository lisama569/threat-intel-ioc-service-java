package com.github.lisama569.threatinteliocservicejava.ioc.service;

import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.ConflictResolver;
import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.IocAggregate;
import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.IocStore;
import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.ReportEntry;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitStatus;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IngestResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizationResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.ioc.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.ioc.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.ioc.source.IntelSource;
import com.github.lisama569.threatinteliocservicejava.ioc.source.IntelSourceRegistry;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * IOC 接入、聚合与命中判定服务。
 * 被拒收的上报会留下拒收记录，使判定结果能区分"被拒收"与"未命中"。
 */
@Service
public class IocService {

    private final IocNormalizer normalizer;
    private final IntelSourceRegistry sourceRegistry;
    private final IocStore store;
    private final ConflictResolver conflictResolver;
    private final Clock clock;

    /** 拒收记录：key 为归一化键（可归一化时）或 RAW:type:value。 */
    private final Map<String, String> rejections = new ConcurrentHashMap<>();

    public IocService(IocNormalizer normalizer,
                      IntelSourceRegistry sourceRegistry,
                      IocStore store,
                      ConflictResolver conflictResolver,
                      Clock iocClock) {
        this.normalizer = normalizer;
        this.sourceRegistry = sourceRegistry;
        this.store = store;
        this.conflictResolver = conflictResolver;
        this.clock = iocClock;
    }

    public IngestResult ingest(IocReport report) {
        NormalizationResult norm = normalizer.normalize(report);
        if (!norm.isOk()) {
            rejections.put(rejectionKey(report), norm.rejectReason() + ": " + norm.detail());
            return IngestResult.rejected(norm.rejectReason(), norm.detail());
        }
        NormalizedIoc ioc = norm.ioc();
        Optional<IntelSource> source = sourceRegistry.find(report.sourceId());
        if (source.isEmpty()) {
            rejections.put(ioc.key(), RejectReason.UNKNOWN_SOURCE + ": " + report.sourceId());
            return IngestResult.rejected(RejectReason.UNKNOWN_SOURCE, "unknown source: " + report.sourceId());
        }
        ReportEntry entry = new ReportEntry(
                report.sourceId(),
                source.get().weight(),
                report.verdict(),
                report.confidence(),
                report.reportedAtEpochMs(),
                report.ttlSeconds());
        store.upsertEntry(ioc, entry);
        rejections.remove(ioc.key());
        return IngestResult.accepted(ioc.key());
    }

    public HitResult lookup(String type, String rawValue) {
        NormalizationResult norm = normalizer.normalizeQuery(type, rawValue);
        if (!norm.isOk()) {
            String rawKey = rawRejectionKey(type, rawValue);
            String recorded = rejections.get(rawKey);
            List<String> basis = new ArrayList<>();
            basis.add("query rejected: " + norm.rejectReason() + ": " + norm.detail());
            if (recorded != null) {
                basis.add("previously rejected report: " + recorded);
            }
            return new HitResult(HitStatus.REJECTED, null, 0.0, basis);
        }
        NormalizedIoc ioc = norm.ioc();
        if (store.isDeleted(ioc)) {
            return new HitResult(HitStatus.DELETED, null, 0.0,
                    List.of("ioc " + ioc.key() + " was deleted"));
        }
        Optional<IocAggregate> aggOpt = store.find(ioc);
        if (aggOpt.isEmpty()) {
            String recorded = rejections.get(ioc.key());
            if (recorded != null) {
                return new HitResult(HitStatus.REJECTED, null, 0.0,
                        List.of("previously rejected report: " + recorded));
            }
            return new HitResult(HitStatus.MISS, null, 0.0,
                    List.of("no intel for " + ioc.key()));
        }
        long now = clock.millis();
        List<ReportEntry> snapshot = aggOpt.get().snapshot();
        List<ReportEntry> active = snapshot.stream().filter(e -> !e.isExpiredAt(now)).toList();
        if (active.isEmpty()) {
            return new HitResult(HitStatus.EXPIRED, null, 0.0,
                    List.of("all " + snapshot.size() + " report(s) expired at " + now));
        }
        ConflictResolver.Resolution resolution = conflictResolver.resolve(active, now);
        List<String> basis = new ArrayList<>();
        basis.add("ioc=" + ioc.key() + " now=" + now);
        basis.addAll(resolution.basis());
        return new HitResult(HitStatus.HIT, resolution.verdict(), resolution.confidence(), basis);
    }

    public boolean delete(String type, String rawValue) {
        NormalizationResult norm = normalizer.normalizeQuery(type, rawValue);
        if (!norm.isOk()) {
            return false;
        }
        boolean removed = store.remove(norm.ioc());
        if (removed) {
            rejections.remove(norm.ioc().key());
        }
        return removed;
    }

    private String rejectionKey(IocReport report) {
        // 类型与值本身可归一化时，用归一化键记录拒收（查询侧同值即可区分）；
        // 否则退化为原始键，保证同一条坏数据能被追踪。
        String t = report.type() == null ? "" : report.type();
        String v = report.rawValue() == null ? "" : report.rawValue();
        NormalizationResult valueNorm = normalizer.normalizeQuery(t, v);
        if (valueNorm.isOk()) {
            return valueNorm.ioc().key();
        }
        return rawRejectionKey(t, v);
    }

    private static String rawRejectionKey(String type, String rawValue) {
        return "RAW:" + type.trim().toUpperCase() + ":" + rawValue.trim();
    }
}
