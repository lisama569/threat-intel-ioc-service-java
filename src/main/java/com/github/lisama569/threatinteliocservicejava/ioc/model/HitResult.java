package com.github.lisama569.threatinteliocservicejava.ioc.model;

import java.util.List;

/** 命中判定结果，携带判定依据以便复现。 */
public record HitResult(
        HitStatus status,
        Verdict verdict,
        double confidence,
        List<String> basis) {
}
