package com.github.lisama569.threatinteliocservicejava.service;

import com.github.lisama569.threatinteliocservicejava.aggregate.ConfidenceAggregator;
import com.github.lisama569.threatinteliocservicejava.aggregate.ConflictArbiter;
import com.github.lisama569.threatinteliocservicejava.config.IocProperties;
import com.github.lisama569.threatinteliocservicejava.model.IocRecord;
import com.github.lisama569.threatinteliocservicejava.model.IocStatus;
import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.RawIocReport;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.model.RejectionRecord;
import com.github.lisama569.threatinteliocservicejava.model.Sighting;
import com.github.lisama569.threatinteliocservicejava.model.Verdict;
import com.github.lisama569.threatinteliocservicejava.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.normalize.NormalizationResult;
import com.github.lisama569.threatinteliocservicejava.source.SourceRegistry;
import com.github.lisama569.threatinteliocservicejava.store.IocStore;
import com.github.lisama569.threatinteliocservicejava.store.StoreEntryView;
import java.time.Clock;
import java.time.Instant;
import java.util.Locale;
import java.util.Optional;
import org.springframework.stereotype.Service;

/** 情报接入、聚合与命中判定的门面。 */
@Service
public class IocService {

    private final IocNormalizer normalizer;
    private final IocStore store;
    private final SourceRegistry sourceRegistry;
    private final ConfidenceAggregator aggregator;
    private final ConflictArbiter arbiter;
    private final IocProperties properties;
    private final Clock clock;

    public IocService(IocNormalizer normalizer, IocStore store, SourceRegistry sourceRegistry,
                      ConfidenceAggregator aggregator, ConflictArbiter arbiter,
                      IocProperties properties, Clock clock) {
        this.normalizer = normalizer;
        this.store = store;
        this.sourceRegistry = sourceRegistry;
        this.aggregator = aggregator;
        this.arbiter = arbiter;
        this.properties = properties;
        this.clock = clock;
    }

    /** 接入一条原始上报：归一化 → 字段校验 → 原子入库 → 返回聚合快照。 */
    public IngestResult ingest(RawIocReport report) {
        Instant now = clock.instant();
        NormalizationResult normalized = normalizer.normalize(report);
        if (!normalized.accepted()) {
            return reject(report, normalized.reason(), normalized.detail(), now);
        }
        Verdict verdict = parseVerdict(report.verdict());
        if (verdict == null) {
            RejectReason reason = report.verdict() == null || report.verdict().isBlank()
                    ? RejectReason.MISSING_VERDICT : RejectReason.UNKNOWN_VERDICT;
            return reject(report, reason, "bad verdict: " + report.verdict(), now);
        }
        if (report.confidence() == null || report.confidence() < 0.0 || report.confidence() > 1.0) {
            return reject(report, RejectReason.INVALID_CONFIDENCE, "confidence must be in [0,1]: " + report.confidence(), now);
        }
        if (report.ttlSeconds() == null || report.ttlSeconds() <= 0) {
            return reject(report, RejectReason.INVALID_TTL, "ttlSeconds must be positive: " + report.ttlSeconds(), now);
        }

        Instant reportedAt = report.reportedAt() != null ? report.reportedAt() : now;
        Instant expiresAt = reportedAt.plusSeconds(report.ttlSeconds());
        Sighting sighting = new Sighting(report.source().trim(), verdict, report.confidence(), reportedAt, expiresAt);
        StoreEntryView view = store.addSighting(normalized.ioc(), sighting, now);
        return IngestResult.ok(normalized.ioc(), toRecord(view, now));
    }

    /** 命中判定：结果区分 HIT / MISS / EXPIRED / DELETED / REJECTED。 */
    public HitResult hit(String type, String value) {
        Instant now = clock.instant();
        NormalizationResult normalized = normalizer.normalize(
                new RawIocReport("hit-query", type, value, "BENIGN", 1.0, now, 1L));
        if (!normalized.accepted()) {
            // 查询本身形态非法：若历史上因此被拒收过，返回留档原因，否则返回本次归一化原因
            Optional<RejectionRecord> rejection = store.findRejection(
                    String.valueOf(type).toLowerCase(Locale.ROOT), String.valueOf(value).toLowerCase(Locale.ROOT));
            return rejection
                    .map(r -> HitResult.rejected(r.reason(), r.detail()))
                    .orElseGet(() -> HitResult.rejected(normalized.reason(), normalized.detail()));
        }

        Optional<StoreEntryView> view = store.find(normalized.ioc());
        if (view.isEmpty()) {
            Optional<RejectionRecord> rejection = store.findRejection(
                    String.valueOf(type).toLowerCase(Locale.ROOT), String.valueOf(value).toLowerCase(Locale.ROOT));
            if (rejection.isPresent()) {
                return HitResult.rejected(rejection.get().reason(), rejection.get().detail());
            }
            return HitResult.of(HitStatus.MISS, null);
        }

        IocRecord record = toRecord(view.get(), now);
        return switch (record.status()) {
            case DELETED -> HitResult.of(HitStatus.DELETED, record);
            case EXPIRED -> HitResult.of(HitStatus.EXPIRED, record);
            case ACTIVE -> isThreatHit(record)
                    ? HitResult.of(HitStatus.HIT, record)
                    : HitResult.of(HitStatus.MISS, record);
        };
    }

    /** 逻辑删除；不存在返回 false。 */
    public boolean delete(String type, String value) {
        NormalizationResult normalized = normalizer.normalize(
                new RawIocReport("delete", type, value, "BENIGN", 1.0, clock.instant(), 1L));
        if (!normalized.accepted()) {
            return false;
        }
        return store.delete(normalized.ioc(), clock.instant()).isPresent();
    }

    private boolean isThreatHit(IocRecord record) {
        return (record.verdict() == Verdict.MALICIOUS || record.verdict() == Verdict.SUSPICIOUS)
                && record.confidence() >= properties.getHitConfidenceThreshold();
    }

    /** 由一致性快照生成聚合记录：状态、仲裁结论、聚合置信度在同一时间点计算。 */
    private IocRecord toRecord(StoreEntryView view, Instant now) {
        IocStatus status;
        if (view.deleted()) {
            status = IocStatus.DELETED;
        } else {
            boolean anyActive = view.sightings().stream().anyMatch(s -> !s.isExpired(now));
            status = anyActive ? IocStatus.ACTIVE : IocStatus.EXPIRED;
        }
        Verdict verdict = arbiter.arbitrate(view.sightings(), sourceRegistry::weightOf, now);
        double confidence = aggregator.aggregate(view.sightings(), sourceRegistry::weightOf, now);
        return new IocRecord(view.ioc(), status, view.sightings(), verdict, confidence, view.updatedAt());
    }

    private IngestResult reject(RawIocReport report, RejectReason reason, String detail, Instant now) {
        if (report != null) {
            store.recordRejection(new RejectionRecord(report.type(), report.value(), reason, detail, now));
        }
        return IngestResult.rejected(reason, detail);
    }

    private static Verdict parseVerdict(String raw) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        try {
            return Verdict.valueOf(raw.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }
}
