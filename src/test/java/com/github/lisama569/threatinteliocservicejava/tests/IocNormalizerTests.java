package com.github.lisama569.threatinteliocservicejava.tests;

import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizationResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.ioc.model.Verdict;
import com.github.lisama569.threatinteliocservicejava.ioc.normalize.IocNormalizer;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.junit.jupiter.api.Assertions.*;

class IocNormalizerTests {

    private static final Logger log = LoggerFactory.getLogger(IocNormalizerTests.class);
    private final IocNormalizer normalizer = new IocNormalizer();

    private IocReport report(String type, String value) {
        return new IocReport("feed-alpha", type, value, Verdict.MALICIOUS, 0.9, 1_000_000L, 3600L);
    }

    private NormalizationResult normalizeAndLog(String type, String value) {
        NormalizationResult r = normalizer.normalize(report(type, value));
        log.info("normalize input=[type={}, value={}] -> {}", type, value,
                r.isOk() ? "OK " + r.ioc().key() : "REJECT " + r.rejectReason() + " (" + r.detail() + ")");
        return r;
    }

    @Test
    void domainNormalizedAcrossForms() {
        assertEquals("DOMAIN:evil.example.com", normalizeAndLog("domain", "Evil.Example.COM.").ioc().key());
        assertEquals("DOMAIN:evil.example.com", normalizeAndLog("DOMAIN", "https://Evil.Example.com/path/x").ioc().key());
        assertEquals("DOMAIN:evil.example.com", normalizeAndLog("DOMAIN", "evil.example.com:8080/").ioc().key());
    }

    @Test
    void urlNormalizedAcrossForms() {
        assertEquals("URL:http://evil.example.com/a",
                normalizeAndLog("url", "HTTP://Evil.Example.COM:80/a#frag").ioc().key());
        assertEquals("URL:https://evil.example.com/",
                normalizeAndLog("URL", "https://evil.example.com:443").ioc().key());
    }

    @Test
    void ipNormalizedWithCidrAndLeadingZeros() {
        assertEquals("IP:10.0.0.1", normalizeAndLog("ip", "10.0.0.1/32").ioc().key());
        assertEquals("IP:10.0.0.1", normalizeAndLog("IP", "010.0.0.1").ioc().key());
    }

    @Test
    void hashNormalizedToLowerCase() {
        String upper = "A".repeat(64);
        assertEquals("HASH:" + "a".repeat(64), normalizeAndLog("hash", upper).ioc().key());
    }

    @Test
    void rejectReasonsAreDistinguishable() {
        assertEquals(RejectReason.INVALID_DOMAIN, normalizeAndLog("domain", "not a domain!!").rejectReason());
        assertEquals(RejectReason.INVALID_DOMAIN, normalizeAndLog("domain", "10.0.0.1").rejectReason());
        assertEquals(RejectReason.INVALID_IP, normalizeAndLog("ip", "10.0.0.256").rejectReason());
        assertEquals(RejectReason.INVALID_IP, normalizeAndLog("ip", "10.0.0.0/24").rejectReason());
        assertEquals(RejectReason.INVALID_URL, normalizeAndLog("url", "ftp://evil.example.com").rejectReason());
        assertEquals(RejectReason.INVALID_HASH, normalizeAndLog("hash", "zzzz").rejectReason());
        assertEquals(RejectReason.UNKNOWN_TYPE, normalizeAndLog("email", "a@b.com").rejectReason());
    }

    @Test
    void missingAndInvalidFieldsRejected() {
        NormalizationResult r1 = normalizer.normalize(
                new IocReport("feed-alpha", "domain", null, Verdict.MALICIOUS, 0.9, 1L, 3600L));
        log.info("normalize input=[null rawValue] -> REJECT {} ({})", r1.rejectReason(), r1.detail());
        assertEquals(RejectReason.MISSING_FIELD, r1.rejectReason());

        NormalizationResult r2 = normalizer.normalize(
                new IocReport("feed-alpha", "domain", "evil.example.com", Verdict.MALICIOUS, 1.5, 1L, 3600L));
        log.info("normalize input=[confidence=1.5] -> REJECT {} ({})", r2.rejectReason(), r2.detail());
        assertEquals(RejectReason.INVALID_CONFIDENCE, r2.rejectReason());

        NormalizationResult r3 = normalizer.normalize(
                new IocReport("feed-alpha", "domain", "evil.example.com", Verdict.MALICIOUS, 0.9, 1L, 0L));
        log.info("normalize input=[ttl=0] -> REJECT {} ({})", r3.rejectReason(), r3.detail());
        assertEquals(RejectReason.INVALID_TTL, r3.rejectReason());
    }
}
