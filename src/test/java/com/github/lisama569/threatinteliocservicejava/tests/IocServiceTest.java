package com.github.lisama569.threatinteliocservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.threatinteliocservicejava.aggregate.ConfidenceAggregator;
import com.github.lisama569.threatinteliocservicejava.aggregate.ConflictArbiter;
import com.github.lisama569.threatinteliocservicejava.config.IocProperties;
import com.github.lisama569.threatinteliocservicejava.model.RawIocReport;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.model.Verdict;
import com.github.lisama569.threatinteliocservicejava.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.service.HitResult;
import com.github.lisama569.threatinteliocservicejava.service.HitStatus;
import com.github.lisama569.threatinteliocservicejava.service.IngestResult;
import com.github.lisama569.threatinteliocservicejava.service.IocService;
import com.github.lisama569.threatinteliocservicejava.source.SourceRegistry;
import com.github.lisama569.threatinteliocservicejava.store.IocStore;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 多来源冲突、重复上报、过期、并发场景的判定测试。 */
class IocServiceTest {

    private static final Logger log = LoggerFactory.getLogger(IocServiceTest.class);
    private static final Instant T0 = Instant.parse("2026-09-28T00:00:00Z");

    /** 可推进的测试时钟，让衰减与过期可预期。 */
    private static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant start) {
            this.now = start;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneId.of("UTC");
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }

    private MutableClock clock;
    private IocProperties properties;
    private SourceRegistry sourceRegistry;
    private IocService service;

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        properties = new IocProperties();
        sourceRegistry = new SourceRegistry();
        ConfidenceAggregator aggregator = new ConfidenceAggregator(properties);
        ConflictArbiter arbiter = new ConflictArbiter(aggregator, properties);
        service = new IocService(new IocNormalizer(), new IocStore(), sourceRegistry,
                aggregator, arbiter, properties, clock);
    }

    private RawIocReport report(String source, String type, String value, String verdict,
                                double confidence, long ttlSeconds) {
        return new RawIocReport(source, type, value, verdict, confidence, clock.instant(), ttlSeconds);
    }

    private void logHit(String label, String type, String value, HitResult hit) {
        log.info("{}: 查询 type={} value={} -> 状态={} 结论={} 聚合置信度={} 上报数={}",
                label, type, value, hit.status(),
                hit.record() != null ? hit.record().verdict() : "-",
                hit.record() != null ? String.format("%.4f", hit.record().confidence()) : "-",
                hit.record() != null ? hit.record().sightingCount() : 0);
    }

    @Test
    void duplicateReportsFromMultipleSourcesMergeAndAggregate() {
        // 同一 IOC 以不同形态重复上报
        IngestResult r1 = service.ingest(report("commercial-feed", "domain", "Evil.COM", "MALICIOUS", 0.9, 86400));
        IngestResult r2 = service.ingest(report("community-feed", "url", "http://evil.com/payload", "MALICIOUS", 0.8, 86400));
        log.info("重复上报归并: r1键={} r2键={}", r1.ioc(), r2.ioc());
        assertEquals(r1.ioc(), r2.ioc());

        HitResult hit = service.hit("DOMAIN", "https://evil.com/x");
        logHit("重复上报聚合", "DOMAIN", "https://evil.com/x", hit);
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(2, hit.record().sightingCount());
        // 1 - (1-0.9*0.9)*(1-0.8*0.6) = 1 - 0.19*0.52 = 0.9012
        assertEquals(0.9012, hit.record().confidence(), 1e-4);
        assertEquals(Verdict.MALICIOUS, hit.record().verdict());
    }

    @Test
    void conflictingVerdictsAreArbitratedDeterministically() {
        service.ingest(report("commercial-feed", "domain", "gray.com", "MALICIOUS", 0.9, 86400));
        service.ingest(report("internal-whitelist", "domain", "gray.com", "WHITELISTED", 1.0, 86400));

        // 规则：可信白名单（权重 1.0 >= 0.8）优先
        HitResult hit1 = service.hit("domain", "gray.com");
        logHit("冲突仲裁-白名单优先", "domain", "gray.com", hit1);
        assertEquals(Verdict.WHITELISTED, hit1.record().verdict());
        assertEquals(HitStatus.MISS, hit1.status());

        // 权重调整后历史判定可复现：白名单源降权后，恶意结论胜出
        sourceRegistry.setWeight("internal-whitelist", 0.5);
        HitResult hit2 = service.hit("domain", "gray.com");
        logHit("冲突仲裁-降权后", "domain", "gray.com", hit2);
        assertEquals(Verdict.MALICIOUS, hit2.record().verdict());
        assertEquals(HitStatus.HIT, hit2.status());

        // 恢复权重，结论复现
        sourceRegistry.setWeight("internal-whitelist", 1.0);
        HitResult hit3 = service.hit("domain", "gray.com");
        logHit("冲突仲裁-权重恢复", "domain", "gray.com", hit3);
        assertEquals(Verdict.WHITELISTED, hit3.record().verdict());
    }

    @Test
    void confidenceDecaysWithAgeAndExpiredIntelNeverHits() {
        // commercial-feed 权重 0.9，置信度 1.0 -> 初始聚合 0.9
        service.ingest(report("commercial-feed", "ip", "203.0.113.7", "MALICIOUS", 1.0, 3 * 86400));

        HitResult fresh = service.hit("ip", "203.0.113.7");
        logHit("过期-刚上报", "ip", "203.0.113.7", fresh);
        assertEquals(HitStatus.HIT, fresh.status());
        assertEquals(0.9, fresh.record().confidence(), 1e-9);

        // 推进一个半衰期：0.9 * 0.5 = 0.45 < 阈值 0.5，不再命中但状态仍 ACTIVE
        clock.advance(Duration.ofDays(1));
        HitResult decayed = service.hit("ip", "203.0.113.7");
        logHit("过期-一个半衰期后", "ip", "203.0.113.7", decayed);
        assertEquals(0.45, decayed.record().confidence(), 1e-9);
        assertEquals(HitStatus.MISS, decayed.status());

        // 推进到 TTL 之后：状态 EXPIRED，与 MISS 明确区分
        clock.advance(Duration.ofDays(3));
        HitResult expired = service.hit("ip", "203.0.113.7");
        logHit("过期-TTL之后", "ip", "203.0.113.7", expired);
        assertEquals(HitStatus.EXPIRED, expired.status());
        assertEquals(0.0, expired.record().confidence(), 1e-9);
    }

    @Test
    void rejectedAndDeletedAreDistinguishableFromMiss() {
        // 未命中：从未见过
        HitResult miss = service.hit("domain", "never-seen.com");
        logHit("区分-未命中", "domain", "never-seen.com", miss);
        assertEquals(HitStatus.MISS, miss.status());

        // 拒收：格式非法，原因可区分
        IngestResult rejected = service.ingest(report("community-feed", "ip", "999.1.1.1", "MALICIOUS", 0.9, 3600));
        log.info("拒收: 原始值=999.1.1.1 原因={} 详情={}", rejected.rejectReason(), rejected.detail());
        assertFalse(rejected.accepted());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, rejected.rejectReason());
        HitResult rejectedHit = service.hit("ip", "999.1.1.1");
        assertEquals(HitStatus.REJECTED, rejectedHit.status());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, rejectedHit.rejectReason());

        // 删除：先接入再删除，墓碑状态 DELETED
        service.ingest(report("honeypot", "domain", "gone.com", "MALICIOUS", 0.9, 86400));
        assertTrue(service.delete("domain", "gone.com"));
        HitResult deleted = service.hit("domain", "gone.com");
        logHit("区分-已删除", "domain", "gone.com", deleted);
        assertEquals(HitStatus.DELETED, deleted.status());
        assertNotNull(deleted.record());
    }

    @Test
    void concurrentIngestAndQueryAreConsistent() throws Exception {
        int threads = 8;
        int perThread = 50;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();

        for (int t = 0; t < threads; t++) {
            String source = "src-" + t;
            sourceRegistry.setWeight(source, 0.5);
            futures.add(pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < perThread; i++) {
                        IngestResult r = service.ingest(
                                report(source, "domain", "Hot.COM", "MALICIOUS", 0.7, 86400));
                        if (!r.accepted()) {
                            throw new IllegalStateException("ingest rejected: " + r.rejectReason());
                        }
                        HitResult h = service.hit("domain", "hot.com");
                        // 并发读取必须看到一致状态：本线程上报已提交，记录必须可见且计数>=1；
                        // 聚合置信度未过阈值时 MISS(带记录) 也是合法一致状态，绝不出现半成品
                        boolean consistent = h.record() != null && h.record().sightingCount() >= 1
                                && (h.status() == HitStatus.HIT || h.status() == HitStatus.MISS);
                        if (!consistent) {
                            throw new IllegalStateException("inconsistent read: " + h.status());
                        }
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get();
        }
        pool.shutdown();

        HitResult hit = service.hit("domain", "hot.com");
        logHit("并发-最终状态", "domain", "hot.com", hit);
        assertEquals(HitStatus.HIT, hit.status());
        // 计数不丢失：8 * 50 次上报全部入账
        assertEquals(threads * perThread, hit.record().sightingCount());
    }
}
