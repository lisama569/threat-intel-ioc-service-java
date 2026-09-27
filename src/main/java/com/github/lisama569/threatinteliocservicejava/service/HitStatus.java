package com.github.lisama569.threatinteliocservicejava.service;

/** 命中判定结果，彼此可区分。 */
public enum HitStatus {
    HIT,
    MISS,
    EXPIRED,
    DELETED,
    REJECTED
}
