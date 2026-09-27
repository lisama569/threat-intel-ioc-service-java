package com.github.lisama569.threatinteliocservicejava.tests;

import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.ConflictResolver;
import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.IocStore;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitStatus;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IngestResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.ioc.model.Verdict;
import com.github.lisama569.threatinteliocservicejava.ioc.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.ioc.service.IocService;
import com.github.lisama569.threatinteliocservicejava.ioc.source.IntelSourceRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.concurrent.atomic.AtomicLong;

import static org.junit.jupiter.api.Assertions.*;

class IocServiceTests {

    private static final Logger log = LoggerFactory.getLogger(IocServiceTests.class);
    private static final long T0 = 1_800_000_000_000L;

    private MutableClock clock;
    private IntelSourceRegistry registry;
    private IocService service;

    /** 可推进的测试时钟，让过期判定可预期。 */
    static class MutableClock extends Clock {
        private final AtomicLong millis;

        MutableClock(long initial) {
            this.millis = new AtomicLong(initial);
        }

        void advanceMs(long delta) {
            millis.addAndGet(delta);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.ofEpochMilli(millis.get());
        }

        @Override
        public long millis() {
            return millis.get();
        }
    }

    @BeforeEach
    void setUp() {
        clock = new MutableClock(T0);
        registry = new IntelSourceRegistry();
        service = new IocService(new IocNormalizer(), registry, new IocStore(),
                new ConflictResolver(), clock);
    }

    private IocReport report(String source, String type, String value,
                             Verdict verdict, double confidence, long ttlSeconds) {
        return new IocReport(source, type, value, verdict, confidence, clock.millis(), ttlSeconds);
    }

    private HitResult lookupAndLog(String type, String value) {
        HitResult r = service.lookup(type, value);
        log.info("lookup input=[type={}, value={}] -> status={} verdict={} confidence={}",
                type, value, r.status(), r.verdict(), String.format("%.4f", r.confidence()));
        r.basis().forEach(b -> log.info("  basis: {}", b));
        return r;
    }

    @Test
    void conflictingSourcesArbitratedByWeight() {
        // alpha(0.9) 报恶意 0.9，beta(0.6) 报白 0.9：刚上报时无衰减
        // MALICIOUS 总分 0.81 > BENIGN 总分 0.54 -> MALICIOUS 胜
        assertTrue(service.ingest(report("feed-alpha", "domain", "Evil.Example.com",
                Verdict.MALICIOUS, 0.9, 3600)).accepted());
        assertTrue(service.ingest(report("feed-beta", "domain", "evil.example.com",
                Verdict.BENIGN, 0.9, 3600)).accepted());

        HitResult hit = lookupAndLog("DOMAIN", "https://EVIL.example.COM/x");
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(Verdict.MALICIOUS, hit.verdict());
        assertEquals(0.81, hit.confidence(), 1e-9);
    }

    @Test
    void conflictArbitrationReproducibleAfterWeightChange() {
        // 上报时固化权重；之后调整注册表权重不影响历史判定
        service.ingest(report("feed-alpha", "ip", "10.9.8.7/32",
                Verdict.MALICIOUS, 0.9, 3600));
        service.ingest(report("feed-gamma", "ip", "10.9.8.7",
                Verdict.BENIGN, 0.9, 3600));
        HitResult before = lookupAndLog("ip", "010.9.8.7");

        registry.register("feed-gamma", 1.0); // 调整权重
        HitResult after = lookupAndLog("ip", "10.9.8.7");

        assertEquals(before.verdict(), after.verdict());
        assertEquals(before.confidence(), after.confidence(), 1e-9);
        assertEquals(Verdict.MALICIOUS, before.verdict()); // 0.81 vs 0.27
    }

    @Test
    void duplicateReportsFromSameSourceKeepLatestOnly() {
        service.ingest(report("feed-alpha", "hash", "A".repeat(64),
                Verdict.SUSPICIOUS, 0.5, 3600));
        service.ingest(report("feed-alpha", "hash", "a".repeat(64),
                Verdict.MALICIOUS, 1.0, 3600));

        HitResult hit = lookupAndLog("hash", "a".repeat(64));
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(Verdict.MALICIOUS, hit.verdict());
        assertEquals(0.9, hit.confidence(), 1e-9); // 1.0 * 0.9(alpha 权重)
    }

    @Test
    void confidenceDecaysWithAge() {
        service.ingest(report("feed-alpha", "domain", "decay.example.com",
                Verdict.MALICIOUS, 1.0, 1000));
        clock.advanceMs(500_000); // 过半 TTL，衰减系数 0.5
        HitResult hit = lookupAndLog("domain", "decay.example.com");
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(0.45, hit.confidence(), 1e-9); // 1.0 * 0.9 * 0.5
    }

    @Test
    void expiredIntelDoesNotParticipate() {
        // beta 短 TTL 先过期，过期后只剩 alpha 的结论参与判定
        service.ingest(report("feed-alpha", "domain", "exp.example.com",
                Verdict.MALICIOUS, 0.9, 3600));
        service.ingest(report("feed-beta", "domain", "exp.example.com",
                Verdict.BENIGN, 0.9, 10));
        clock.advanceMs(11_000); // beta 已过期

        HitResult hit = lookupAndLog("domain", "exp.example.com");
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(Verdict.MALICIOUS, hit.verdict());

        clock.advanceMs(3600_000L); // 全部过期
        HitResult expired = lookupAndLog("domain", "exp.example.com");
        assertEquals(HitStatus.EXPIRED, expired.status());
    }

    @Test
    void rejectedDeletedAndMissAreDistinguishable() {
        // 拒收：格式非法
        IngestResult bad = service.ingest(report("feed-alpha", "domain", "not a domain!!",
                Verdict.MALICIOUS, 0.9, 3600));
        log.info("ingest invalid -> accepted={} reason={} detail={}",
                bad.accepted(), bad.rejectReason(), bad.detail());
        assertFalse(bad.accepted());
        assertEquals(RejectReason.INVALID_DOMAIN, bad.rejectReason());
        assertEquals(HitStatus.REJECTED, lookupAndLog("domain", "not a domain!!").status());

        // 拒收：未知来源
        IngestResult unknownSrc = service.ingest(report("feed-nobody", "domain", "ghost.example.com",
                Verdict.MALICIOUS, 0.9, 3600));
        log.info("ingest unknown source -> accepted={} reason={}",
                unknownSrc.accepted(), unknownSrc.rejectReason());
        assertEquals(RejectReason.UNKNOWN_SOURCE, unknownSrc.rejectReason());
        assertEquals(HitStatus.REJECTED, lookupAndLog("domain", "ghost.example.com").status());

        // 删除后可区分
        service.ingest(report("feed-alpha", "domain", "gone.example.com",
                Verdict.MALICIOUS, 0.9, 3600));
        assertTrue(service.delete("domain", "Gone.Example.COM."));
        assertEquals(HitStatus.DELETED, lookupAndLog("domain", "gone.example.com").status());

        // 从未见过
        assertEquals(HitStatus.MISS, lookupAndLog("domain", "never.example.com").status());
    }
}
