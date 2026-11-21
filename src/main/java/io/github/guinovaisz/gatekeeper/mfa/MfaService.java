package io.github.guinovaisz.gatekeeper.mfa;

import java.time.*;
import java.sql.Timestamp;
import java.util.*;
import org.apache.commons.codec.binary.Base32;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.shared.*;
import io.github.guinovaisz.gatekeeper.session.RevocationService;

@Service
public class MfaService {
    private final JdbcTemplate db; private final IdentityRepository identities; private final SecretBox box;
    private final Clock clock; private final PasswordEncoder encoder; private final AuditService audit; private final RevocationService revocation;
    public MfaService(JdbcTemplate db,IdentityRepository identities,SecretBox box,Clock clock,PasswordEncoder encoder,AuditService audit,RevocationService revocation) {
        this.db=db;this.identities=identities;this.box=box;this.clock=clock;this.encoder=encoder;this.audit=audit;this.revocation=revocation;
    }
    @Transactional public String begin(UUID id,String password) {
        Identity identity=identities.lock(id);
        if(identity.mfaSecret()!=null || !encoder.matches(password,identity.passwordHash())) throw new IllegalArgumentException("Enrollment rejected");
        String secret=new Base32().encodeAsString(Secrets.bytes(20));
        db.update("UPDATE identity_account SET mfa_pending=?,mfa_pending_until=? WHERE id=?",box.seal(secret),Timestamp.from(clock.instant().plusSeconds(300)),id);
        audit.record(id,"MFA_ENROLLMENT_STARTED","SUCCESS",id);
        return secret;
    }
    @Transactional public List<String> activate(UUID id,String code) {
        Identity identity=identities.lock(id);
        if(identity.mfaPending()==null || !clock.instant().isBefore(identity.pendingUntil())) throw new IllegalArgumentException("Enrollment rejected");
        long step=Totp.match(box.open(identity.mfaPending()),code,clock.instant().getEpochSecond()/30,-1);
        if(step<0) throw new IllegalArgumentException("Credential rejected");
        db.update("UPDATE identity_account SET mfa_secret=mfa_pending,mfa_pending=NULL,mfa_pending_until=NULL,mfa_last_step=? WHERE id=?",step,id);
        List<String> codes=generate(id);
        revocation.all(id); audit.record(id,"MFA_ENROLLED","SUCCESS",id);
        return codes;
    }
    @Transactional public boolean verify(UUID id,String code,boolean recovery) {
        Identity identity=identities.lock(id);
        if(!identity.state().equals("ACTIVE") || identity.mfaSecret()==null) return false;
        if(recovery) {
            boolean accepted=db.update("DELETE FROM recovery_code WHERE identity_id=? AND digest=?",id,Secrets.digest(code))==1;
            if(accepted) audit.record(id,"RECOVERY_CODE_USED","SUCCESS",id);
            return accepted;
        }
        long step=Totp.match(box.open(identity.mfaSecret()),code,clock.instant().getEpochSecond()/30,identity.lastStep());
        if(step<0) return false;
        db.update("UPDATE identity_account SET mfa_last_step=? WHERE id=?",step,id);
        audit.record(id,"MFA_VERIFIED","SUCCESS",id);
        return true;
    }
    @Transactional public List<String> regenerate(UUID id,String password,String code) {
        Identity identity=identities.lock(id);
        if(!encoder.matches(password,identity.passwordHash()) || !verify(id,code,false)) throw new IllegalArgumentException("Credential rejected");
        List<String> codes=generate(id); audit.record(id,"RECOVERY_CODES_REGENERATED","SUCCESS",id); return codes;
    }
    @Transactional public void disable(UUID id,String password,String code) {
        Identity identity=identities.lock(id);
        if(!encoder.matches(password,identity.passwordHash()) || !verify(id,code,false)) throw new IllegalArgumentException("Credential rejected");
        db.update("UPDATE identity_account SET mfa_secret=NULL,mfa_pending=NULL,mfa_pending_until=NULL,mfa_last_step=-1 WHERE id=?",id);
        db.update("DELETE FROM recovery_code WHERE identity_id=?",id); revocation.all(id); audit.record(id,"MFA_DISABLED","SUCCESS",id);
    }
    private List<String> generate(UUID id) {
        db.update("DELETE FROM recovery_code WHERE identity_id=?",id);
        List<String> codes=new ArrayList<>();
        for(int i=0;i<10;i++) { String code=Secrets.token(16); codes.add(code); db.update("INSERT INTO recovery_code VALUES (?,?)",id,Secrets.digest(code)); }
        return codes;
    }
}
