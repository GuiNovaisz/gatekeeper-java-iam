package io.github.guinovaisz.gatekeeper.oauth;

import java.sql.Timestamp;
import java.time.*;
import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.*;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.transaction.PlatformTransactionManager;
import io.github.guinovaisz.gatekeeper.shared.Secrets;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.identity.*;

/** Decorates official providers with a PostgreSQL consistency boundary. */
public class SerializedGrantProvider implements AuthenticationProvider {
    private final AuthenticationProvider delegate; private final JdbcTemplate db;
    private final OAuth2AuthorizationService authorizations;private final TransactionTemplate tx;
    private final Clock clock;private final AuditService audit;private final IdentityRepository identities;
    public SerializedGrantProvider(AuthenticationProvider delegate,JdbcTemplate db,OAuth2AuthorizationService authorizations,PlatformTransactionManager transactions,Clock clock,AuditService audit,IdentityRepository identities) {
        this.delegate=delegate;this.db=db;this.authorizations=authorizations;this.tx=new TransactionTemplate(transactions);this.clock=clock;this.audit=audit;this.identities=identities;
    }
    private record Result(Authentication value,OAuth2AuthenticationException error) {}
    @Override public Authentication authenticate(Authentication input) {
        boolean refresh=input instanceof OAuth2RefreshTokenAuthenticationToken;
        String token=refresh?((OAuth2RefreshTokenAuthenticationToken)input).getRefreshToken():((OAuth2AuthorizationCodeAuthenticationToken)input).getCode();
        String digest=Secrets.digest(token);
        Result result=tx.execute(status->{
            // Stable token hash lock also covers a missing/deleted authorization.
            db.queryForList("SELECT pg_advisory_xact_lock(hashtextextended(?,0))",digest);
            List<String> spent=refresh?db.queryForList("SELECT authorization_id FROM spent_refresh WHERE digest=?",String.class,digest):List.of();
            if(!spent.isEmpty()) {
                // Serialize against descendants by locking the authorization row before removal.
                db.queryForList("SELECT id FROM oauth2_authorization WHERE id=? FOR UPDATE",spent.getFirst());
                db.update("DELETE FROM oauth2_authorization WHERE id=?",spent.getFirst());
                audit.record(null,"REFRESH_REPLAY","DENIED",null);
                return new Result(null,invalid()); // commit the family revocation before throwing
            }
            OAuth2Authorization found=authorizations.findByToken(token,refresh?OAuth2TokenType.REFRESH_TOKEN:new OAuth2TokenType("code"));
            if(found==null) return new Result(null,invalid());
            // Lock identity first: same order as password reset/disable and revocation.
            Identity identity=identities.lock(UUID.fromString(found.getPrincipalName()));
            if(!identity.state().equals("ACTIVE")) return new Result(null,invalid());
            db.queryForList("SELECT id FROM oauth2_authorization WHERE id=? FOR UPDATE",found.getId());
            OAuth2Authorization current=authorizations.findByToken(token,refresh?OAuth2TokenType.REFRESH_TOKEN:new OAuth2TokenType("code"));
            if(current==null) return new Result(null,invalid());
            try {
                Authentication output=delegate.authenticate(input);
                if(refresh) db.update("INSERT INTO spent_refresh VALUES (?,?,?) ON CONFLICT DO NOTHING",digest,found.getId(),Timestamp.from(clock.instant().plus(Duration.ofMinutes(35))));
                audit.record(identity.id(),refresh?"TOKEN_REFRESHED":"TOKEN_ISSUED","SUCCESS",identity.id());
                return new Result(output,null);
            } catch(OAuth2AuthenticationException e) {return new Result(null,e);}
        });
        if(result.error()!=null) throw result.error();
        return result.value();
    }
    private static OAuth2AuthenticationException invalid(){return new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_GRANT);}
    @Override public boolean supports(Class<?> type){return delegate.supports(type);}
}
