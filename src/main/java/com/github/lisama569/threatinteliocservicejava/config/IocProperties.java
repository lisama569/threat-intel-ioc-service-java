package com.github.lisama569.threatinteliocservicejava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** 可调参数：衰减半衰期、命中阈值、白名单仲裁权重阈值。 */
@Component
@ConfigurationProperties(prefix = "ioc")
public class IocProperties {

    /** 置信度衰减半衰期（秒）。 */
    private long halfLifeSeconds = 86400;

    /** 聚合置信度达到该阈值才算命中。 */
    private double hitConfidenceThreshold = 0.5;

    /** 白名单来源权重达到该阈值时优先仲裁为白名单。 */
    private double whitelistWeightThreshold = 0.8;

    public long getHalfLifeSeconds() {
        return halfLifeSeconds;
    }

    public void setHalfLifeSeconds(long halfLifeSeconds) {
        this.halfLifeSeconds = halfLifeSeconds;
    }

    public double getHitConfidenceThreshold() {
        return hitConfidenceThreshold;
    }

    public void setHitConfidenceThreshold(double hitConfidenceThreshold) {
        this.hitConfidenceThreshold = hitConfidenceThreshold;
    }

    public double getWhitelistWeightThreshold() {
        return whitelistWeightThreshold;
    }

    public void setWhitelistWeightThreshold(double whitelistWeightThreshold) {
        this.whitelistWeightThreshold = whitelistWeightThreshold;
    }
}
