package com.github.lisama569.threatinteliocservicejava.model;

/** 归一化后的 IOC，作为聚合与查询的唯一键。 */
public record NormalizedIoc(IocType type, String value) {

    public String key() {
        return type + ":" + value;
    }

    @Override
    public String toString() {
        return key();
    }
}
