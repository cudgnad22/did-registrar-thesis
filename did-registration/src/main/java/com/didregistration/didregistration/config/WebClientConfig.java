package com.didregistration.didregistration.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;

@Configuration
public class WebClientConfig {

    /** WebClient trỏ tới module did:cheqd nội bộ (thay cho Universal Registrar). */
    @Bean
    public WebClient cheqdModuleWebClient(@Value("${cheqd.module.url}") String baseUrl) {
        return WebClient.builder()
                .baseUrl(baseUrl)
                .build();
    }
}
