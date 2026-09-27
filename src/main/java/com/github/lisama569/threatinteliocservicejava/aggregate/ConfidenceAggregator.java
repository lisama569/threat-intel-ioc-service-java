package com.github.lisama569.threatinteliocservicejava.aggregate;

import com.github.lisama569.threatinteliocservicejava.config.IocProperties;
import com.github.lisama569.threatinteliocservicejava.model.Sighting;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.function.ToDoubleFunction;
import org.springframework.stereotype.Component;

/**
 * 置信度聚合：
 * <ol>
 *   <li>单次上报有效置信度 = 原始置信度 × 来源权重 × 时间衰减因子；</li>
 *   <li>时间衰减因子 = 0.5 ^ (age / halfLife)，过期上报不参与聚合；</li>
 *   <li>多次上报按独立证据合并：1 - Π(1 - effective_i)。</li>
 * </ol>
 * 同一输入（sightings、权重、now、halfLife）必然得到同一结果，可复现。
 */
@Component
public class ConfidenceAggregator {

    private final IocProperties properties;

    public ConfidenceAggregator(IocProperties properties) {
        this.properties = properties;
    }

    public double aggregate(List<Sighting> sightings, ToDoubleFunction<String> sourceWeight, Instant now) {
        double productOfMiss = 1.0;
        boolean any = false;
        for (Sighting s : sightings) {
            if (s.isExpired(now)) {
                continue;
            }
            any = true;
            double effective = effectiveConfidence(s, sourceWeight.applyAsDouble(s.source()), now);
            productOfMiss *= (1.0 - effective);
        }
        if (!any) {
            return 0.0;
        }
        return 1.0 - productOfMiss;
    }

    /** 单次上报的有效置信度，供日志与仲裁复用。 */
    public double effectiveConfidence(Sighting s, double sourceWeight, Instant now) {
        long ageSeconds = Math.max(0, Duration.between(s.reportedAt(), now).getSeconds());
        double decay = Math.pow(0.5, (double) ageSeconds / properties.getHalfLifeSeconds());
        return clamp01(s.confidence() * sourceWeight * decay);
    }

    private static double clamp01(double v) {
        return Math.max(0.0, Math.min(1.0, v));
    }
}
