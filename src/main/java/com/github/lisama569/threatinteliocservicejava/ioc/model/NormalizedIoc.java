package com.github.lisama569.threatinteliocservicejava.ioc.model;

/** 归一化后的 IOC，作为聚合与命中的唯一键。 */
public record NormalizedIoc(IocType type, String value) {
    public String key() {
        return type + ":" + value;
    }
}
