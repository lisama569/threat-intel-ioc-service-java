package com.github.lisama569.threatinteliocservicejava.service;

import com.github.lisama569.threatinteliocservicejava.model.IocRecord;
import com.github.lisama569.threatinteliocservicejava.model.NormalizedIoc;
import com.github.lisama569.threatinteliocservicejava.model.RejectReason;

/** 接入结果：成功时给出归一化键与聚合快照，失败时给出拒绝原因。 */
public record IngestResult(
        boolean accepted,
        NormalizedIoc ioc,
        IocRecord record,
        RejectReason rejectReason,
        String detail) {

    public static IngestResult ok(NormalizedIoc ioc, IocRecord record) {
        return new IngestResult(true, ioc, record, null, null);
    }

    public static IngestResult rejected(RejectReason reason, String detail) {
        return new IngestResult(false, null, null, reason, detail);
    }
}
