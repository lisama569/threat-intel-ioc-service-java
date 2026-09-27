package com.github.lisama569.threatinteliocservicejava.ioc.model;

/** 归一化结果：要么成功给出 NormalizedIoc，要么失败给出可区分的 RejectReason。 */
public record NormalizationResult(NormalizedIoc ioc, RejectReason rejectReason, String detail) {

    public static NormalizationResult ok(NormalizedIoc ioc) {
        return new NormalizationResult(ioc, null, null);
    }

    public static NormalizationResult reject(RejectReason reason, String detail) {
        return new NormalizationResult(null, reason, detail);
    }

    public boolean isOk() {
        return ioc != null;
    }
}
