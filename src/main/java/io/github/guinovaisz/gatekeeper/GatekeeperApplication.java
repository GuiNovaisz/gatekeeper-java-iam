package io.github.guinovaisz.gatekeeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class GatekeeperApplication {
    public static void main(String[] args) { SpringApplication.run(GatekeeperApplication.class, args); }
}
