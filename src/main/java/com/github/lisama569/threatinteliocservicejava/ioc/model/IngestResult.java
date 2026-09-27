package com.github.lisama569.threatinteliocservicejava.ioc.model;

/** 上报受理结果。 */
public record IngestResult(boolean accepted, RejectReason rejectReason, String detail, String iocKey) {

    public static IngestResult accepted(String iocKey) {
        return new IngestResult(true, null, null, iocKey);
    }

    public static IngestResult rejected(RejectReason reason, String detail) {
        return new IngestResult(false, reason, detail, null);
    }
}
