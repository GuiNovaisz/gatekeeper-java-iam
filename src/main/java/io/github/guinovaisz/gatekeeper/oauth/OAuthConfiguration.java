package io.github.guinovaisz.gatekeeper.oauth;

import java.time.Duration;
import java.util.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.*;
import org.springframework.security.oauth2.server.authorization.settings.*;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.identity.*;

@Configuration
public class OAuthConfiguration {
    @Bean RegisteredClientRepository registeredClients(JdbcTemplate db){return new JdbcRegisteredClientRepository(db);}
    @Bean OAuth2AuthorizationService authorizations(JdbcTemplate db,RegisteredClientRepository clients){return new JdbcOAuth2AuthorizationService(db,clients);}
    @Bean OAuth2AuthorizationConsentService consents(JdbcTemplate db,RegisteredClientRepository clients){return new JdbcOAuth2AuthorizationConsentService(db,clients);}
    @Bean AuthorizationServerSettings serverSettings(@Value("${gatekeeper.issuer}") String issuer) {
        if(!issuer.startsWith("https://") && !issuer.matches("http://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?")) throw new IllegalArgumentException("Issuer requires TLS outside loopback");
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }
    @Bean OAuth2TokenCustomizer<JwtEncodingContext> claims(IdentityRepository identities) {
        return context->{
            if(OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                Identity identity=identities.find(UUID.fromString(context.getPrincipal().getName())).orElseThrow();
                context.getClaims().audience(List.of("gatekeeper-resource")).claim("cv",identity.credentialVersion());
            }
        };
    }
    @Bean ApplicationRunner bootstrap(IdentityService identities,IdentityRepository repository,RegisteredClientRepository clients,PasswordEncoder encoder,AuditService audit,
            @Value("${gatekeeper.bootstrap-login}") String login,@Value("${gatekeeper.bootstrap-password}") String password,@Value("${gatekeeper.client-secret}") String clientSecret) {
        return args->{
            if(clientSecret.length()<32) throw new IllegalArgumentException("Demo confidential secret requires >=32 characters");
            if(!login.isBlank() && repository.byLogin(login).isEmpty()) identities.register(login,password,true);
            seed(clients,encoder,audit,"gatekeeper-public",false,clientSecret);
            seed(clients,encoder,audit,"gatekeeper-confidential",true,clientSecret);
        };
    }
    private void seed(RegisteredClientRepository clients,PasswordEncoder encoder,AuditService audit,String id,boolean confidential,String secret) {
        if(clients.findByClientId(id)!=null) return;
        RegisteredClient.Builder builder=RegisteredClient.withId(UUID.randomUUID().toString()).clientId(id)
            .clientAuthenticationMethod(confidential?ClientAuthenticationMethod.CLIENT_SECRET_BASIC:ClientAuthenticationMethod.NONE)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUri("http://127.0.0.1:9090/callback")
            .scope(OidcScopes.OPENID).scope("resource.read")
            .clientSettings(ClientSettings.builder().requireProofKey(true).requireAuthorizationConsent(false).build())
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(5)).authorizationCodeTimeToLive(Duration.ofSeconds(60))
                .refreshTokenTimeToLive(Duration.ofMinutes(30)).reuseRefreshTokens(false).idTokenSignatureAlgorithm(SignatureAlgorithm.RS256).build());
        if(confidential) builder.clientSecret(encoder.encode(secret)).authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
        clients.save(builder.build());audit.record(null,"CLIENT_REGISTERED","SUCCESS",null);
    }
}
