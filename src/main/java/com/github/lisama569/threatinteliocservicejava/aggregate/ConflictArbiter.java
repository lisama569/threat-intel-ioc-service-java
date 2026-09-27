package com.github.lisama569.threatinteliocservicejava.aggregate;

import com.github.lisama569.threatinteliocservicejava.config.IocProperties;
import com.github.lisama569.threatinteliocservicejava.model.Sighting;
import com.github.lisama569.threatinteliocservicejava.model.Verdict;
import java.time.Instant;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import java.util.function.ToDoubleFunction;
import org.springframework.stereotype.Component;

/**
 * 来源结论冲突时的确定性仲裁规则（按序适用）：
 * <ol>
 *   <li>过期上报不参与仲裁；</li>
 *   <li>若存在来源权重 ≥ whitelistWeightThreshold 的 WHITELISTED 上报，结论为 WHITELISTED
 *       （可信白名单优先，避免误杀）；</li>
 *   <li>否则按结论分组累计有效置信度（置信度 × 来源权重 × 时间衰减），得分最高者胜；</li>
 *   <li>得分并列时按严重度取 MALICIOUS &gt; SUSPICIOUS &gt; BENIGN &gt; WHITELISTED。</li>
 * </ol>
 * 规则与权重确定时，相同历史输入必然复现相同结论。
 */
@Component
public class ConflictArbiter {

    private static final List<Verdict> SEVERITY_ORDER =
            List.of(Verdict.MALICIOUS, Verdict.SUSPICIOUS, Verdict.BENIGN, Verdict.WHITELISTED);

    private static final double SCORE_EPSILON = 1e-9;

    private final ConfidenceAggregator aggregator;
    private final IocProperties properties;

    public ConflictArbiter(ConfidenceAggregator aggregator, IocProperties properties) {
        this.aggregator = aggregator;
        this.properties = properties;
    }

    /** 返回仲裁结论；无有效（未过期）上报时返回 null。 */
    public Verdict arbitrate(List<Sighting> sightings, ToDoubleFunction<String> sourceWeight, Instant now) {
        List<Sighting> active = sightings.stream().filter(s -> !s.isExpired(now)).toList();
        if (active.isEmpty()) {
            return null;
        }

        // 规则 2：可信白名单优先
        boolean trustedWhitelist = active.stream()
                .filter(s -> s.verdict() == Verdict.WHITELISTED)
                .anyMatch(s -> sourceWeight.applyAsDouble(s.source()) >= properties.getWhitelistWeightThreshold());
        if (trustedWhitelist) {
            return Verdict.WHITELISTED;
        }

        // 规则 3：按结论累计有效置信度
        Map<Verdict, Double> scores = new EnumMap<>(Verdict.class);
        for (Sighting s : active) {
            double effective = aggregator.effectiveConfidence(s, sourceWeight.applyAsDouble(s.source()), now);
            scores.merge(s.verdict(), effective, Double::sum);
        }

        // 规则 4：最高分胜，并列按严重度
        Verdict best = null;
        double bestScore = -1.0;
        for (Verdict v : SEVERITY_ORDER) {
            double score = scores.getOrDefault(v, 0.0);
            if (score > bestScore + SCORE_EPSILON) {
                best = v;
                bestScore = score;
            }
        }
        return best;
    }
}
