package com.github.lisama569.threatinteliocservicejava.ioc.normalize;

import com.github.lisama569.threatinteliocservicejava.ioc.model.IocReport;
import com.github.lisama569.threatinteliocservicejava.ioc.model.IocType;
import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizationResult;
import com.github.lisama569.threatinteliocservicejava.ioc.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.ioc.model.RejectReason;
import org.springframework.stereotype.Component;

import java.util.Locale;

/**
 * IOC 归一化与格式校验。
 * 规则：
 * - DOMAIN：去协议前缀与路径、小写化、去结尾点，校验标签格式；
 * - IP：仅 IPv4，八位组 0-255，去掉前导零；/32 的 CIDR 归并为单 IP；
 * - URL：scheme/host 小写、去默认端口、去 fragment、空路径归一为 "/"；
 * - HASH：小写 hex，长度须为 32(MD5)/40(SHA1)/64(SHA256)。
 */
@Component
public class IocNormalizer {

    public NormalizationResult normalize(IocReport report) {
        if (report == null) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "report is null");
        }
        if (isBlank(report.sourceId())) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "sourceId is blank");
        }
        if (isBlank(report.type())) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "type is blank");
        }
        if (isBlank(report.rawValue())) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "rawValue is blank");
        }
        if (report.verdict() == null) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "verdict is null");
        }
        if (report.confidence() == null) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "confidence is null");
        }
        double c = report.confidence();
        if (Double.isNaN(c) || c < 0.0 || c > 1.0) {
            return NormalizationResult.reject(RejectReason.INVALID_CONFIDENCE,
                    "confidence must be in [0,1]: " + c);
        }
        if (report.reportedAtEpochMs() == null) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "reportedAtEpochMs is null");
        }
        if (report.ttlSeconds() == null) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "ttlSeconds is null");
        }
        if (report.ttlSeconds() <= 0) {
            return NormalizationResult.reject(RejectReason.INVALID_TTL,
                    "ttlSeconds must be positive: " + report.ttlSeconds());
        }

        IocType type = parseType(report.type());
        if (type == null) {
            return NormalizationResult.reject(RejectReason.UNKNOWN_TYPE, "unknown type: " + report.type());
        }
        return normalizeTypedValue(type, report.rawValue());
    }

    /** 查询侧归一化：只校验类型与值，与上报侧使用完全相同的规则。 */
    public NormalizationResult normalizeQuery(String type, String rawValue) {
        if (isBlank(type)) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "type is blank");
        }
        if (isBlank(rawValue)) {
            return NormalizationResult.reject(RejectReason.MISSING_FIELD, "rawValue is blank");
        }
        IocType t = parseType(type);
        if (t == null) {
            return NormalizationResult.reject(RejectReason.UNKNOWN_TYPE, "unknown type: " + type);
        }
        return normalizeTypedValue(t, rawValue);
    }

    private static IocType parseType(String type) {
        try {
            return IocType.valueOf(type.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            return null;
        }
    }

    private NormalizationResult normalizeTypedValue(IocType type, String rawValue) {
        return switch (type) {
            case DOMAIN -> normalizeDomain(rawValue);
            case IP -> normalizeIp(rawValue);
            case URL -> normalizeUrl(rawValue);
            case HASH -> normalizeHash(rawValue);
        };
    }

    private NormalizationResult normalizeDomain(String raw) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        // 允许以 URL 形态上报域名：去协议前缀与路径
        int schemeIdx = v.indexOf("://");
        if (schemeIdx >= 0) {
            v = v.substring(schemeIdx + 3);
        }
        int slashIdx = v.indexOf('/');
        if (slashIdx >= 0) {
            v = v.substring(0, slashIdx);
        }
        int colonIdx = v.indexOf(':');
        if (colonIdx >= 0) {
            v = v.substring(0, colonIdx); // 去端口
        }
        while (v.endsWith(".")) {
            v = v.substring(0, v.length() - 1);
        }
        if (!isValidDomain(v)) {
            return NormalizationResult.reject(RejectReason.INVALID_DOMAIN, "invalid domain: " + raw);
        }
        return NormalizationResult.ok(new NormalizedIoc(IocType.DOMAIN, v));
    }

    static boolean isValidDomain(String v) {
        if (v.isEmpty() || v.length() > 253) {
            return false;
        }
        String[] labels = v.split("\\.", -1);
        if (labels.length < 2) {
            return false;
        }
        for (String label : labels) {
            if (label.isEmpty() || label.length() > 63) {
                return false;
            }
            if (label.startsWith("-") || label.endsWith("-")) {
                return false;
            }
            for (int i = 0; i < label.length(); i++) {
                char ch = label.charAt(i);
                if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                    return false;
                }
            }
        }
        // 最后一段不能全数字（避免把 IP 当域名）
        String tld = labels[labels.length - 1];
        for (int i = 0; i < tld.length(); i++) {
            if (!Character.isLetter(tld.charAt(i))) {
                return false;
            }
        }
        return true;
    }

    private NormalizationResult normalizeIp(String raw) {
        String v = raw.trim();
        // /32 的 CIDR 归并为单 IP
        int slashIdx = v.indexOf('/');
        if (slashIdx >= 0) {
            String prefix = v.substring(slashIdx + 1);
            if (!"32".equals(prefix)) {
                return NormalizationResult.reject(RejectReason.INVALID_IP,
                        "only /32 CIDR can be normalized to a single IP: " + raw);
            }
            v = v.substring(0, slashIdx);
        }
        String[] parts = v.split("\\.", -1);
        if (parts.length != 4) {
            return NormalizationResult.reject(RejectReason.INVALID_IP, "invalid ipv4: " + raw);
        }
        int[] octets = new int[4];
        for (int i = 0; i < 4; i++) {
            String p = parts[i];
            if (p.isEmpty() || p.length() > 3) {
                return NormalizationResult.reject(RejectReason.INVALID_IP, "invalid ipv4 octet: " + raw);
            }
            for (int j = 0; j < p.length(); j++) {
                if (!Character.isDigit(p.charAt(j))) {
                    return NormalizationResult.reject(RejectReason.INVALID_IP, "invalid ipv4 octet: " + raw);
                }
            }
            int n = Integer.parseInt(p);
            if (n > 255) {
                return NormalizationResult.reject(RejectReason.INVALID_IP, "ipv4 octet out of range: " + raw);
            }
            octets[i] = n;
        }
        // 规范化去掉前导零
        String canonical = octets[0] + "." + octets[1] + "." + octets[2] + "." + octets[3];
        return NormalizationResult.ok(new NormalizedIoc(IocType.IP, canonical));
    }

    private NormalizationResult normalizeUrl(String raw) {
        String v = raw.trim();
        int schemeIdx = v.indexOf("://");
        if (schemeIdx <= 0) {
            return NormalizationResult.reject(RejectReason.INVALID_URL, "url missing scheme: " + raw);
        }
        String scheme = v.substring(0, schemeIdx).toLowerCase(Locale.ROOT);
        if (!scheme.equals("http") && !scheme.equals("https")) {
            return NormalizationResult.reject(RejectReason.INVALID_URL, "unsupported scheme: " + raw);
        }
        String rest = v.substring(schemeIdx + 3);
        // 去 fragment
        int fragIdx = rest.indexOf('#');
        if (fragIdx >= 0) {
            rest = rest.substring(0, fragIdx);
        }
        String authority;
        String pathAndQuery;
        int slashIdx = rest.indexOf('/');
        if (slashIdx >= 0) {
            authority = rest.substring(0, slashIdx);
            pathAndQuery = rest.substring(slashIdx);
        } else {
            authority = rest;
            pathAndQuery = "/";
        }
        // 拆分 host 与端口
        String host = authority.toLowerCase(Locale.ROOT);
        Integer port = null;
        int colonIdx = host.lastIndexOf(':');
        if (colonIdx >= 0) {
            String portStr = host.substring(colonIdx + 1);
            host = host.substring(0, colonIdx);
            if (portStr.isEmpty() || portStr.length() > 5) {
                return NormalizationResult.reject(RejectReason.INVALID_URL, "invalid port: " + raw);
            }
            for (int i = 0; i < portStr.length(); i++) {
                if (!Character.isDigit(portStr.charAt(i))) {
                    return NormalizationResult.reject(RejectReason.INVALID_URL, "invalid port: " + raw);
                }
            }
            port = Integer.parseInt(portStr);
            if (port > 65535) {
                return NormalizationResult.reject(RejectReason.INVALID_URL, "port out of range: " + raw);
            }
        }
        if (!isValidDomain(host) && !isValidIpv4(host)) {
            return NormalizationResult.reject(RejectReason.INVALID_URL, "invalid url host: " + raw);
        }
        // 去默认端口
        boolean defaultPort = port != null
                && ((scheme.equals("http") && port == 80) || (scheme.equals("https") && port == 443));
        StringBuilder sb = new StringBuilder();
        sb.append(scheme).append("://").append(host);
        if (port != null && !defaultPort) {
            sb.append(':').append(port);
        }
        sb.append(pathAndQuery.isEmpty() ? "/" : pathAndQuery);
        return NormalizationResult.ok(new NormalizedIoc(IocType.URL, sb.toString()));
    }

    private static boolean isValidIpv4(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            if (p.isEmpty() || p.length() > 3) {
                return false;
            }
            for (int i = 0; i < p.length(); i++) {
                if (!Character.isDigit(p.charAt(i))) {
                    return false;
                }
            }
            if (Integer.parseInt(p) > 255) {
                return false;
            }
        }
        return true;
    }

    private NormalizationResult normalizeHash(String raw) {
        String v = raw.trim().toLowerCase(Locale.ROOT);
        int len = v.length();
        if (len != 32 && len != 40 && len != 64) {
            return NormalizationResult.reject(RejectReason.INVALID_HASH,
                    "hash length must be 32/40/64: " + raw);
        }
        for (int i = 0; i < len; i++) {
            char ch = v.charAt(i);
            boolean hex = (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
            if (!hex) {
                return NormalizationResult.reject(RejectReason.INVALID_HASH, "hash not hex: " + raw);
            }
        }
        return NormalizationResult.ok(new NormalizedIoc(IocType.HASH, v));
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
