package io.github.guinovaisz.gatekeeper.security;

import java.time.Clock;
import java.util.Map;
import org.springframework.context.annotation.*;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.*;

@Configuration
public class CoreConfiguration {
    @Bean Clock clock() { return Clock.systemUTC(); }
    @Bean PasswordEncoder passwordEncoder() {
        return new DelegatingPasswordEncoder("argon2id", Map.of("argon2id", new Argon2PasswordEncoder(16,32,1,19456,2)));
    }
}
