package com.github.lisama569.threatinteliocservicejava.ioc.model;

/** 命中判定状态：未命中 / 命中 / 曾被拒收 / 已删除 / 已过期。 */
public enum HitStatus {
    HIT,
    MISS,
    REJECTED,
    DELETED,
    EXPIRED
}
