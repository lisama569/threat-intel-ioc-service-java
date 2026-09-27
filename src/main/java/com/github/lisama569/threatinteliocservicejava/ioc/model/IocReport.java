package com.github.lisama569.threatinteliocservicejava.ioc.model;

/**
 * 一条原始情报上报。type/rawValue 保持原始字符串，
 * 非法类型或格式在归一化阶段以 RejectReason 拒绝。
 */
public record IocReport(
        String sourceId,
        String type,
        String rawValue,
        Verdict verdict,
        Double confidence,
        Long reportedAtEpochMs,
        Long ttlSeconds) {
}
