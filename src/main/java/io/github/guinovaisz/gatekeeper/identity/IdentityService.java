package io.github.guinovaisz.gatekeeper.identity;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.credential.PasswordPolicy;
import io.github.guinovaisz.gatekeeper.session.RevocationService;

@Service
public class IdentityService {
    private final JdbcTemplate db; private final IdentityRepository identities;
    private final PasswordEncoder encoder; private final Clock clock;
    private final AuditService audit; private final RevocationService revocation;
    public IdentityService(JdbcTemplate db, IdentityRepository identities, PasswordEncoder encoder, Clock clock, AuditService audit, RevocationService revocation) {
        this.db=db;this.identities=identities;this.encoder=encoder;this.clock=clock;this.audit=audit;this.revocation=revocation;
    }
    @Transactional public UUID register(String login, String password, boolean admin) {
        PasswordPolicy.validate(password);
        String normalized=IdentityRepository.normalize(login);
        if(normalized.length()>254 || !normalized.matches("[a-z0-9][a-z0-9@._+\\-]{2,253}")) throw new IllegalArgumentException("Invalid login format");
        UUID id=UUID.randomUUID();
        // ON CONFLICT avoids an exception oracle and preserves transaction usability.
        int inserted=db.update("INSERT INTO identity_account(id,login,password_hash,created_at) VALUES (?,?,?,?) ON CONFLICT(login) DO NOTHING",id,normalized,encoder.encode(password),Timestamp.from(clock.instant()));
        if(inserted==0) return null;
        db.update("INSERT INTO identity_role VALUES (?,?)",id,admin?"ADMIN":"USER");
        audit.record(id,"REGISTRATION","SUCCESS",id);
        return id;
    }
    @Transactional public void changePassword(UUID id, String current, String replacement) {
        Identity identity=identities.lock(id);
        if(!encoder.matches(current,identity.passwordHash())) throw new IllegalArgumentException("Credential rejected");
        PasswordPolicy.validate(replacement);
        db.update("UPDATE identity_account SET password_hash=? WHERE id=?",encoder.encode(replacement),id);
        revocation.all(id); audit.record(id,"PASSWORD_CHANGED","SUCCESS",id);
    }
    @Transactional public void state(UUID actor, UUID target, String state) {
        if(!java.util.Set.of("ACTIVE","LOCKED","DISABLED").contains(state)) throw new IllegalArgumentException("Invalid state");
        identities.lock(target);
        db.update("UPDATE identity_account SET state=? WHERE id=?",state,target);
        revocation.all(target); audit.record(actor,"IDENTITY_STATE_CHANGED","SUCCESS",target);
    }
}
