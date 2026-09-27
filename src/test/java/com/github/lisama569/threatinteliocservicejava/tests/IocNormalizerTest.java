package com.github.lisama569.threatinteliocservicejava.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.lisama569.threatinteliocservicejava.model.IocType;
import com.github.lisama569.threatinteliocservicejava.model.RawIocReport;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;
import com.github.lisama569.threatinteliocservicejava.normalize.IocNormalizer;
import com.github.lisama569.threatinteliocservicejava.normalize.NormalizationResult;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** 归一化规则与可区分拒绝原因的单元测试。 */
class IocNormalizerTest {

    private static final Logger log = LoggerFactory.getLogger(IocNormalizerTest.class);

    private final IocNormalizer normalizer = new IocNormalizer();

    private RawIocReport report(String type, String value) {
        return new RawIocReport("community-feed", type, value, "MALICIOUS", 0.9, Instant.now(), 3600L);
    }

    private NormalizationResult normalizeAndLog(String type, String value) {
        NormalizationResult result = normalizer.normalize(report(type, value));
        if (result.accepted()) {
            log.info("归一化成功: 原始输入 type={} value={} -> 归一化键 {}", type, value, result.ioc());
        } else {
            log.info("归一化拒绝: 原始输入 type={} value={} -> 原因={} 详情={}", type, value, result.reason(), result.detail());
        }
        return result;
    }

    @Test
    void sameIocInDifferentShapesMergesToSameKey() {
        NormalizationResult plain = normalizeAndLog("domain", "Example.COM");
        NormalizationResult withDot = normalizeAndLog("domain", "example.com.");
        NormalizationResult withScheme = normalizeAndLog("domain", "http://Example.COM:8080/path?q=1");
        NormalizationResult asUrl = normalizeAndLog("url", "https://EXAMPLE.com/evil");
        assertTrue(plain.accepted() && withDot.accepted() && withScheme.accepted() && asUrl.accepted());
        assertEquals(IocType.DOMAIN, plain.ioc().type());
        assertEquals(plain.ioc(), withDot.ioc());
        assertEquals(plain.ioc(), withScheme.ioc());
        assertEquals(plain.ioc(), asUrl.ioc());
    }

    @Test
    void urlWithIpHostAndSingleAddressCidrFoldToIp() {
        NormalizationResult asUrl = normalizeAndLog("url", "http://10.0.0.1:8080/bad");
        NormalizationResult asIp = normalizeAndLog("ip", "10.0.0.1");
        NormalizationResult asCidr32 = normalizeAndLog("cidr", "10.0.0.1/32");
        assertEquals(IocType.IP, asUrl.ioc().type());
        assertEquals(asIp.ioc(), asUrl.ioc());
        assertEquals(asIp.ioc(), asCidr32.ioc());
    }

    @Test
    void cidrNormalizesToNetworkAddress() {
        NormalizationResult result = normalizeAndLog("cidr", "10.0.3.7/24");
        assertTrue(result.accepted());
        assertEquals(IocType.CIDR, result.ioc().type());
        assertEquals("10.0.3.0/24", result.ioc().value());
    }

    @Test
    void hashIsLowercased() {
        NormalizationResult upper = normalizeAndLog("hash", "A" + "B".repeat(63));
        NormalizationResult lower = normalizeAndLog("sha256", "a" + "b".repeat(63));
        assertTrue(upper.accepted() && lower.accepted());
        assertEquals(upper.ioc(), lower.ioc());
    }

    @Test
    void rejectReasonsAreDistinguishable() {
        assertEquals(RejectReason.MISSING_SOURCE,
                normalizer.normalize(new RawIocReport(" ", "domain", "a.com", "MALICIOUS", 0.5, null, 1L)).reason());
        assertEquals(RejectReason.MISSING_TYPE,
                normalizer.normalize(new RawIocReport("s", null, "a.com", "MALICIOUS", 0.5, null, 1L)).reason());
        assertEquals(RejectReason.MISSING_VALUE,
                normalizer.normalize(new RawIocReport("s", "domain", "  ", "MALICIOUS", 0.5, null, 1L)).reason());
        assertEquals(RejectReason.UNKNOWN_TYPE, normalizeAndLog("email", "a@b.com").reason());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, normalizeAndLog("domain", "bad_domain!.com").reason());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, normalizeAndLog("ip", "10.0.0.256").reason());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, normalizeAndLog("ip", "10.0.0").reason());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, normalizeAndLog("cidr", "10.0.0.0/33").reason());
        assertEquals(RejectReason.INVALID_VALUE_FORMAT, normalizeAndLog("hash", "zzzz").reason());
        assertFalse(normalizeAndLog("domain", "singlelabel").accepted());
    }
}
