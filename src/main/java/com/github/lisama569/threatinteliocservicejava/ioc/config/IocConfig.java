package com.github.lisama569.threatinteliocservicejava.ioc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/** 提供可替换的时钟，测试中用固定时钟让过期判定可预期。 */
@Configuration
public class IocConfig {

    @Bean
    public Clock iocClock() {
        return Clock.systemUTC();
    }
}
