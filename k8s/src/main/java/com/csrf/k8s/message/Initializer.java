package com.csrf.k8s.message;

import org.springframework.security.access.SecurityConfig;
import org.springframework.session.web.context.AbstractHttpSessionApplicationInitializer;

public class Initializer extends AbstractHttpSessionApplicationInitializer {
    public Initializer() {
        super(SecurityConfig.class, RedisConfig.class);
    }
}
