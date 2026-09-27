package com.github.lisama569.threatinteliocservicejava.service;

import com.github.lisama569.threatinteliocservicejava.model.IocRecord;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;

/** 命中判定输出。 */
public record HitResult(
        HitStatus status,
        IocRecord record,
        RejectReason rejectReason,
        String detail) {

    public static HitResult of(HitStatus status, IocRecord record) {
        return new HitResult(status, record, null, null);
    }

    public static HitResult rejected(RejectReason reason, String detail) {
        return new HitResult(HitStatus.REJECTED, null, reason, detail);
    }
}
