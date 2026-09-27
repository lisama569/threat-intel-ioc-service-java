package com.github.lisama569.threatinteliocservicejava.normalize;

import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;

/** 归一化结果：要么成功得到 NormalizedIoc，要么携带可区分的拒绝原因。 */
public record NormalizationResult(
        boolean accepted,
        NormalizedIoc ioc,
        RejectReason reason,
        String detail) {

    public static NormalizationResult ok(NormalizedIoc ioc) {
        return new NormalizationResult(true, ioc, null, null);
    }

    public static NormalizationResult reject(RejectReason reason, String detail) {
        return new NormalizationResult(false, null, reason, detail);
    }
}
