package com.github.lisama569.threatinteliocservicejava.ioc.aggregate;

import com.github.lisama569.threatinteliocservicejava.ioc.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * 来源结论冲突仲裁（规则确定、可复现）：
 * 1. 只统计未过期的上报；
 * 2. 每条上报的有效置信度 = confidence * sourceWeight * 时间衰减；
 * 3. 按结论分组求和，总分最高者胜出；
 * 4. 平分按固定优先级 MALICIOUS > SUSPICIOUS > BENIGN 打破；
 * 5. 聚合置信度为胜方总分，封顶 1.0。
 */
@Component
public class ConflictResolver {

    public Resolution resolve(List<ReportEntry> activeEntries, long nowEpochMs) {
        Map<Verdict, Double> totals = new EnumMap<>(Verdict.class);
        List<String> basis = new ArrayList<>();
        for (ReportEntry e : activeEntries) {
            double eff = e.effectiveConfidenceAt(nowEpochMs);
            totals.merge(e.verdict(), eff, Double::sum);
            basis.add(String.format(
                    "source=%s verdict=%s confidence=%.4f weight=%.2f effective=%.4f reportedAt=%d ttl=%ds",
                    e.sourceId(), e.verdict(), e.confidence(), e.sourceWeight(), eff,
                    e.reportedAtEpochMs(), e.ttlSeconds()));
        }
        Verdict winner = null;
        double best = -1.0;
        // 固定遍历顺序即平分时的优先级
        for (Verdict v : List.of(Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN)) {
            double total = totals.getOrDefault(v, 0.0);
            basis.add(String.format("total[%s]=%.4f", v, total));
            if (total > best) {
                best = total;
                winner = v;
            }
        }
        if (winner == null) {
            winner = Verdict.BENIGN;
            best = 0.0;
        }
        double confidence = Math.min(1.0, best);
        basis.add(String.format("winner=%s aggregatedConfidence=%.4f", winner, confidence));
        return new Resolution(winner, confidence, basis);
    }

    /** 裁决结果：结论、聚合置信度、判定依据（用于复现）。 */
    public record Resolution(Verdict verdict, double confidence, List<String> basis) {
    }
}
