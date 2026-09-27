package com.github.lisama569.threatinteliocservicejava.ioc.source;

import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * 内存中的假情报源注册表，模拟多个外部情报源。
 * 预置三个来源，权重不同；支持运行时调整权重（调整后历史判定可复现，
 * 因为每条上报都固化了当时的来源权重）。
 */
@Component
public class IntelSourceRegistry {

    private final Map<String, IntelSource> sources = new ConcurrentHashMap<>();

    public IntelSourceRegistry() {
        register("feed-alpha", 0.9);
        register("feed-beta", 0.6);
        register("feed-gamma", 0.3);
    }

    public void register(String id, double weight) {
        if (id == null || id.isBlank()) {
            throw new IllegalArgumentException("source id blank");
        }
        if (weight < 0.0 || weight > 1.0) {
            throw new IllegalArgumentException("weight must be in [0,1]");
        }
        sources.put(id, new IntelSource(id, weight));
    }

    public Optional<IntelSource> find(String sourceId) {
        return Optional.ofNullable(sources.get(sourceId));
    }

    public double weightOf(String sourceId) {
        IntelSource s = sources.get(sourceId);
        if (s == null) {
            throw new IllegalArgumentException("unknown source: " + sourceId);
        }
        return s.weight();
    }
}
