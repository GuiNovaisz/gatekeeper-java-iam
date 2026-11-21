package io.github.guinovaisz.gatekeeper.session;

import java.util.UUID;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.github.guinovaisz.gatekeeper.audit.AuditService;

@Service
public class RevocationService {
    private final JdbcTemplate db; private final AuditService audit;
    public RevocationService(JdbcTemplate db, AuditService audit) {this.db=db;this.audit=audit;}
    @Transactional public void all(UUID id) {
        db.update("UPDATE identity_account SET credential_version=credential_version+1 WHERE id=?",id);
        db.update("DELETE FROM spring_session WHERE principal_name=?",id.toString());
        db.update("DELETE FROM oauth2_authorization WHERE principal_name=?",id.toString());
        audit.record(id,"CREDENTIALS_REVOKED","SUCCESS",id);
    }
}
