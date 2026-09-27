package com.github.lisama569.threatinteliocservicejava.tests;

import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.ConflictResolver;
import com.github.lisama569.threatinteliocservicejava.ioc.aggregate.IocStore;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.HitStatus;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.model.Verdict;
import com.github.lisama569.threatinteliocservicejava.ioc.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.ioc.service.IocService;
import com.github.lisama569.threatinteliocservicejava.ioc.source.IntelSourceRegistry;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.*;

class IocConcurrencyTests {

    private static final Logger log = LoggerFactory.getLogger(IocConcurrencyTests.class);
    private static final long T0 = 1_800_000_000_000L;

    private IocService newService(IntelSourceRegistry registry) {
        return new IocService(new IocNormalizer(), registry, new IocStore(),
                new ConflictResolver(), Clock.systemUTC());
    }

    @Test
    void concurrentIngestFromManySourcesLosesNothing() throws Exception {
        IntelSourceRegistry registry = new IntelSourceRegistry();
        int sources = 32;
        for (int i = 0; i < sources; i++) {
            registry.register("src-" + i, 0.5);
        }
        IocService service = newService(registry);

        ExecutorService pool = Executors.newFixedThreadPool(16);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < sources; i++) {
            String src = "src-" + i;
            futures.add(pool.submit(() -> {
                await(start);
                for (int round = 0; round < 50; round++) {
                    // 同一 IOC 以不同形态重复上报
                    String value = round % 2 == 0 ? "Evil.Example.com" : "https://EVIL.example.COM/";
                    assertTrue(service.ingest(new IocReport(src, "domain", value,
                            Verdict.MALICIOUS, 0.8, T0, 3600L)).accepted());
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(30, TimeUnit.SECONDS);
        }
        pool.shutdown();

        HitResult hit = service.lookup("domain", "evil.example.com");
        log.info("concurrent ingest done -> status={} verdict={} confidence={}",
                hit.status(), hit.verdict(), String.format("%.4f", hit.confidence()));
        hit.basis().forEach(b -> log.info("  basis: {}", b));
        assertEquals(HitStatus.HIT, hit.status());
        assertEquals(Verdict.MALICIOUS, hit.verdict());
        // 32 个来源 * 0.8 * 0.5 权重 = 12.8，封顶 1.0；且每个来源只保留最新一条
        assertEquals(1.0, hit.confidence(), 1e-9);
        long contributing = hit.basis().stream().filter(b -> b.startsWith("source=")).count();
        assertEquals(sources, contributing);
    }

    @Test
    void concurrentLookupSeesConsistentState() throws Exception {
        IntelSourceRegistry registry = new IntelSourceRegistry();
        IocService service = newService(registry);
        service.ingest(new IocReport("feed-alpha", "ip", "10.1.2.3",
                Verdict.MALICIOUS, 0.9, T0, 3600L));

        int readers = 16;
        ExecutorService pool = Executors.newFixedThreadPool(readers);
        CountDownLatch start = new CountDownLatch(1);
        List<Future<HitResult>> futures = new ArrayList<>();
        for (int i = 0; i < readers; i++) {
            futures.add(pool.submit(() -> {
                await(start);
                return service.lookup("ip", "10.1.2.3/32");
            }));
        }
        start.countDown();
        for (Future<HitResult> f : futures) {
            HitResult r = f.get(10, TimeUnit.SECONDS);
            assertEquals(HitStatus.HIT, r.status());
            assertEquals(Verdict.MALICIOUS, r.verdict());
        }
        pool.shutdown();
    }

    @Test
    void concurrentDeleteHasSingleWinnerAndConsistentOutcome() throws Exception {
        IntelSourceRegistry registry = new IntelSourceRegistry();
        IocService service = newService(registry);
        service.ingest(new IocReport("feed-alpha", "domain", "race.example.com",
                Verdict.MALICIOUS, 0.9, T0, 3600L));

        int deleters = 8;
        ExecutorService pool = Executors.newFixedThreadPool(deleters);
        CountDownLatch start = new CountDownLatch(1);
        AtomicInteger deleteWins = new AtomicInteger();
        List<Future<?>> futures = new ArrayList<>();
        for (int i = 0; i < deleters; i++) {
            futures.add(pool.submit(() -> {
                await(start);
                if (service.delete("domain", "Race.Example.COM.")) {
                    deleteWins.incrementAndGet();
                }
            }));
        }
        start.countDown();
        for (Future<?> f : futures) {
            f.get(10, TimeUnit.SECONDS);
        }
        pool.shutdown();

        assertEquals(1, deleteWins.get(), "exactly one delete may succeed");
        HitResult after = service.lookup("domain", "race.example.com");
        log.info("after concurrent delete -> status={}", after.status());
        assertEquals(HitStatus.DELETED, after.status());
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }
}
