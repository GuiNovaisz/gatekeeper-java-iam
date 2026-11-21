package io.github.guinovaisz.gatekeeper.credential;

import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.shared.Secrets;
import io.github.guinovaisz.gatekeeper.session.RevocationService;

@Service
public class RecoveryService {
    private final JdbcTemplate db; private final IdentityRepository identities; private final Clock clock;
    private final PasswordEncoder encoder; private final RecoveryDelivery delivery; private final RevocationService revocation; private final AuditService audit;
    public RecoveryService(JdbcTemplate db,IdentityRepository identities,Clock clock,PasswordEncoder encoder,RecoveryDelivery delivery,RevocationService revocation,AuditService audit) {
        this.db=db;this.identities=identities;this.clock=clock;this.encoder=encoder;this.delivery=delivery;this.revocation=revocation;this.audit=audit;
    }
    @Transactional public void request(String login) {
        // Generate even for unknown identities; no raw credential is persisted.
        String token=Secrets.token(32);
        identities.byLogin(login).filter(i->i.state().equals("ACTIVE")).ifPresent(identity->{
            identities.lock(identity.id());
            db.update("DELETE FROM password_reset WHERE identity_id=?",identity.id());
            db.update("INSERT INTO password_reset(digest,identity_id,expires_at) VALUES (?,?,?)",Secrets.digest(token),identity.id(),Timestamp.from(clock.instant().plusSeconds(600)));
            // Local provider is deterministic; production integration must use an encrypted outbox.
            delivery.deliver(identity.id(),token);
            audit.record(null,"RESET_REQUESTED","SUCCESS",identity.id());
        });
    }
    @Transactional public void reset(String token,String replacement) {
        PasswordPolicy.validate(replacement);
        String digest=Secrets.digest(token);
        List<UUID> ids=db.queryForList("SELECT identity_id FROM password_reset WHERE digest=?",UUID.class,digest);
        if(ids.isEmpty()) throw new IllegalArgumentException("Credential rejected");
        UUID id=ids.getFirst(); Identity identity=identities.lock(id);
        if(!identity.state().equals("ACTIVE")) throw new IllegalArgumentException("Credential rejected");
        int claimed=db.update("UPDATE password_reset SET consumed_at=? WHERE digest=? AND consumed_at IS NULL AND expires_at>?",Timestamp.from(clock.instant()),digest,Timestamp.from(clock.instant()));
        if(claimed!=1) throw new IllegalArgumentException("Credential rejected");
        db.update("UPDATE identity_account SET password_hash=? WHERE id=?",encoder.encode(replacement),id);
        revocation.all(id); audit.record(id,"PASSWORD_RESET","SUCCESS",id);
    }
}
