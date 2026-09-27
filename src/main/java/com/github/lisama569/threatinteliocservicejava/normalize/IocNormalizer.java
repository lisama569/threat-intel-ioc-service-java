package com.github.lisama569.threatinteliocservicejava.normalize;

import com.github.lisama569.threatinteliocservicejava.model.IocType;
import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.RawIocReport;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;
import java.net.URI;
import java.util.Locale;
import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

/**
 * 把不同形态的原始上报归并到统一的 NormalizedIoc：
 * <ul>
 *   <li>大小写归一（域名、哈希统一小写）；</li>
 *   <li>带协议前缀的 URL 提取 host，折叠为 DOMAIN 或 IP；</li>
 *   <li>CIDR 归并到网络地址，/32 单地址折叠为 IP；</li>
 *   <li>哈希统一小写并校验十六进制长度。</li>
 * </ul>
 * 字段缺失或格式错误返回可区分的 RejectReason，绝不静默跳过。
 */
@Component
public class IocNormalizer {

    private static final Pattern DOMAIN_LABEL = Pattern.compile("[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?");
    private static final Pattern HEX = Pattern.compile("[0-9a-f]+");

    public NormalizationResult normalize(RawIocReport report) {
        if (report == null) {
            return NormalizationResult.reject(RejectReason.MISSING_VALUE, "report is null");
        }
        if (isBlank(report.source())) {
            return NormalizationResult.reject(RejectReason.MISSING_SOURCE, "source is blank");
        }
        if (isBlank(report.type())) {
            return NormalizationResult.reject(RejectReason.MISSING_TYPE, "type is blank");
        }
        if (isBlank(report.value())) {
            return NormalizationResult.reject(RejectReason.MISSING_VALUE, "value is blank");
        }

        String rawType = report.type().trim().toLowerCase(Locale.ROOT);
        String rawValue = report.value().trim();
        return switch (rawType) {
            case "domain" -> normalizeDomain(rawValue);
            case "ip", "ipv4" -> normalizeIp(rawValue);
            case "cidr", "network" -> normalizeCidr(rawValue);
            case "url" -> normalizeUrl(rawValue);
            case "hash", "md5", "sha1", "sha256" -> normalizeHash(rawValue);
            default -> NormalizationResult.reject(RejectReason.UNKNOWN_TYPE, "unknown type: " + report.type());
        };
    }

    /** 域名：容忍协议前缀与路径，统一小写、去末尾点。 */
    private NormalizationResult normalizeDomain(String raw) {
        String host = extractHost(raw);
        if (host == null) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "cannot extract host from: " + raw);
        }
        return validateDomain(host);
    }

    private NormalizationResult validateDomain(String host) {
        String domain = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (domain.isEmpty() || domain.length() > 253) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad domain length: " + host);
        }
        String[] labels = domain.split("\\.");
        if (labels.length < 2) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "domain needs at least two labels: " + host);
        }
        for (String label : labels) {
            if (!DOMAIN_LABEL.matcher(label).matches()) {
                return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad domain label '" + label + "' in: " + host);
            }
        }
        if (!labels[labels.length - 1].matches("[a-z]{2,}")) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad TLD in: " + host);
        }
        return NormalizationResult.ok(new NormalizedIoc(IocType.DOMAIN, domain));
    }

    /** IP：容忍协议前缀，仅支持 IPv4 点分十进制。 */
    private NormalizationResult normalizeIp(String raw) {
        String host = extractHost(raw);
        if (host == null) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "cannot extract ip from: " + raw);
        }
        return validateIp(host);
    }

    private NormalizationResult validateIp(String host) {
        String[] parts = host.split("\\.", -1);
        if (parts.length != 4) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "not an IPv4 address: " + host);
        }
        StringBuilder canonical = new StringBuilder();
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || !part.chars().allMatch(Character::isDigit)) {
                return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad octet '" + part + "' in: " + host);
            }
            int octet = Integer.parseInt(part);
            if (octet > 255 || (part.length() > 1 && part.startsWith("0"))) {
                return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad octet '" + part + "' in: " + host);
            }
            canonical.append(octet).append('.');
        }
        canonical.setLength(canonical.length() - 1);
        return NormalizationResult.ok(new NormalizedIoc(IocType.IP, canonical.toString()));
    }

    /** CIDR：归并到网络地址；/32 折叠为 IP。 */
    private NormalizationResult normalizeCidr(String raw) {
        int slash = raw.indexOf('/');
        if (slash <= 0 || slash == raw.length() - 1) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "cidr needs prefix length: " + raw);
        }
        String ipPart = raw.substring(0, slash);
        String prefixPart = raw.substring(slash + 1);
        int prefix;
        try {
            prefix = Integer.parseInt(prefixPart);
        } catch (NumberFormatException e) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "bad prefix length in: " + raw);
        }
        if (prefix < 0 || prefix > 32) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "prefix out of range in: " + raw);
        }
        NormalizationResult ipResult = validateIp(ipPart);
        if (!ipResult.accepted()) {
            return ipResult;
        }
        if (prefix == 32) {
            return NormalizationResult.ok(new NormalizedIoc(IocType.IP, ipResult.ioc().value()));
        }
        long mask = prefix == 0 ? 0L : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long ipLong = toLong(ipResult.ioc().value());
        long network = ipLong & mask;
        return NormalizationResult.ok(new NormalizedIoc(IocType.CIDR, toDotted(network) + "/" + prefix));
    }

    /** URL：提取 host，IP 折叠为 IP，否则折叠为 DOMAIN。 */
    private NormalizationResult normalizeUrl(String raw) {
        String host = extractHost(raw);
        if (host == null) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "cannot extract host from url: " + raw);
        }
        if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            return validateIp(host);
        }
        return validateDomain(host);
    }

    /** 哈希：统一小写，校验十六进制与长度（MD5/SHA1/SHA256）。 */
    private NormalizationResult normalizeHash(String raw) {
        String hash = raw.toLowerCase(Locale.ROOT);
        int len = hash.length();
        if (len != 32 && len != 40 && len != 64) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT,
                    "hash length must be 32/40/64, got " + len + ": " + raw);
        }
        if (!HEX.matcher(hash).matches()) {
            return NormalizationResult.reject(RejectReason.INVALID_VALUE_FORMAT, "hash is not hex: " + raw);
        }
        return NormalizationResult.ok(new NormalizedIoc(IocType.HASH, hash));
    }

    /** 去掉协议前缀、端口、路径与查询串，返回小写 host；无法解析返回 null。 */
    private String extractHost(String raw) {
        String value = raw.trim().toLowerCase(Locale.ROOT);
        if (value.contains("://")) {
            try {
                URI uri = URI.create(value);
                String host = uri.getHost();
                return host == null ? null : host;
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
        // 无协议前缀：截掉第一个 '/' 之后的路径部分，再去掉端口
        int slash = value.indexOf('/');
        String hostPort = slash >= 0 ? value.substring(0, slash) : value;
        int colon = hostPort.indexOf(':');
        String host = colon >= 0 ? hostPort.substring(0, colon) : hostPort;
        return host.isEmpty() ? null : host;
    }

    private static long toLong(String ip) {
        long result = 0;
        for (String part : ip.split("\\.")) {
            result = (result << 8) | Integer.parseInt(part);
        }
        return result;
    }

    private static String toDotted(long ip) {
        return ((ip >>> 24) & 0xFF) + "." + ((ip >>> 16) & 0xFF) + "." + ((ip >>> 8) & 0xFF) + "." + (ip & 0xFF);
    }

    private static boolean isBlank(String s) {
        return s == null || s.isBlank();
    }
}
