package io.github.guinovaisz.gatekeeper.authentication;

import java.time.Duration;
import java.util.*;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.security.Throttle;

@Service
public class LocalAuthentication {
    private final IdentityRepository identities; private final PasswordEncoder encoder;
    private final Throttle throttle; private final AuditService audit; private final String dummy;
    public LocalAuthentication(IdentityRepository identities, PasswordEncoder encoder, Throttle throttle, AuditService audit) {
        this.identities=identities;this.encoder=encoder;this.throttle=throttle;this.audit=audit;
        dummy=encoder.encode(io.github.guinovaisz.gatekeeper.shared.Secrets.token(32));
    }
    public Identity password(String login, String password, String source) {
        boolean sourceAllowed=throttle.allow("login-source",source,30,Duration.ofMinutes(5));
        boolean accountAllowed=throttle.allow("login-account",IdentityRepository.normalize(login),8,Duration.ofMinutes(5));
        if(!sourceAllowed || !accountAllowed) { audit.record(null,"LOGIN_THROTTLED","DENIED",null); throw denied(); }
        Optional<Identity> candidate=identities.byLogin(login);
        boolean valid=encoder.matches(password,candidate.map(Identity::passwordHash).orElse(dummy));
        if(!valid || candidate.isEmpty() || !candidate.get().state().equals("ACTIVE")) {
            audit.record(candidate.map(Identity::id).orElse(null),"LOGIN_FAILURE","DENIED",null); throw denied();
        }
        return candidate.get();
    }
    private static BadCredentialsException denied() { return new BadCredentialsException("Authentication rejected"); }
}
