package com.github.lisama569.threatinteliocservicejava.config;

import java.time.Clock;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** 提供可替换的 Clock，测试可注入固定时钟以复现衰减与过期行为。 */
@Configuration
public class IocConfig {

    @Bean
    public Clock iocClock() {
        return Clock.systemUTC();
    }
}
