package com.github.lisama569.threatinteliocservicejava.source;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 内存假数据源注册表：模拟多个外部情报源及其权重。
 * 未注册来源使用默认权重，权重可在线调整（调整后重算即可复现历史判定）。
 */
@Component
public class SourceRegistry {

    public static final double DEFAULT_SOURCE_WEIGHT = 0.3;

    private final Map<String, Double> weights = new ConcurrentHashMap<>();

    public SourceRegistry() {
        // 内置假数据源：商业源权重最高，社区源次之
        weights.put("commercial-feed", 0.9);
        weights.put("community-feed", 0.6);
        weights.put("internal-whitelist", 1.0);
        weights.put("honeypot", 0.5);
    }

    public double weightOf(String source) {
        if (source == null) {
            return DEFAULT_SOURCE_WEIGHT;
        }
        return weights.getOrDefault(source.trim().toLowerCase(java.util.Locale.ROOT), DEFAULT_SOURCE_WEIGHT);
    }

    public void setWeight(String source, double weight) {
        if (weight < 0.0 || weight > 1.0) {
            throw new IllegalArgumentException("weight must be in [0,1]: " + weight);
        }
        weights.put(source.trim().toLowerCase(java.util.Locale.ROOT), weight);
    }

    public Map<String, Double> snapshot() {
        return Map.copyOf(weights);
    }
}
