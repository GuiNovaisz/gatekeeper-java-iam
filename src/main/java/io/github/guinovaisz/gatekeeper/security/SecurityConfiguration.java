package io.github.guinovaisz.gatekeeper.security;

import java.time.Clock;
import java.util.*;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.*;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.csrf.*;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.transaction.PlatformTransactionManager;
import io.github.guinovaisz.gatekeeper.oauth.SerializedGrantProvider;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.session.RevocationService;

@Configuration
public class SecurityConfiguration {
    @Bean @Order(1) SecurityFilterChain protocol(HttpSecurity http,JdbcTemplate db,OAuth2AuthorizationService authorizations,
            PlatformTransactionManager transactions,Clock clock,AuditService audit,IdentityRepository identities,Throttle throttle) throws Exception {
        OAuth2AuthorizationServerConfigurer server=OAuth2AuthorizationServerConfigurer.authorizationServer();
        http.securityMatcher(server.getEndpointsMatcher())
            .with(server,as->as.oidc(Customizer.withDefaults())
                .authorizationEndpoint(endpoint->endpoint.authenticationProviders(providers->providers.forEach(provider->{
                    if(provider instanceof OAuth2AuthorizationCodeRequestAuthenticationProvider request) {
                        request.setAuthenticationValidator(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_REDIRECT_URI_VALIDATOR
                            .andThen(OAuth2AuthorizationCodeRequestAuthenticationValidator.DEFAULT_SCOPE_VALIDATOR).andThen(context->{
                                OAuth2AuthorizationCodeRequestAuthenticationToken input=context.getAuthentication();
                                Object method=input.getAdditionalParameters().get("code_challenge_method");
                                Object challenge=input.getAdditionalParameters().get("code_challenge");
                                if(!context.getRegisteredClient().getRedirectUris().contains(input.getRedirectUri()))
                                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),null);
                                if(!"S256".equals(method) || !(challenge instanceof String text) || !text.matches("[A-Za-z0-9_-]{43}")) {
                                    throw new OAuth2AuthorizationCodeRequestAuthenticationException(new OAuth2Error(OAuth2ErrorCodes.INVALID_REQUEST),input);
                                }
                            }));
                    }
                })))
                .tokenRevocationEndpoint(endpoint->endpoint.revocationResponseHandler((request,response,authentication)->{
                    audit.record(null,"TOKEN_REVOKED","SUCCESS",null);response.setStatus(200);
                }))
                .tokenEndpoint(endpoint->endpoint.authenticationProviders(providers->{
                    for(int i=0;i<providers.size();i++) {
                        var provider=providers.get(i);
                        if(provider instanceof OAuth2RefreshTokenAuthenticationProvider || provider instanceof OAuth2AuthorizationCodeAuthenticationProvider)
                            providers.set(i,new SerializedGrantProvider(provider,db,authorizations,transactions,clock,audit,identities));
                    }
                })))
            .authorizeHttpRequests(auth->auth.anyRequest().authenticated())
            // SAS precisely excludes its protocol POST endpoints from CSRF; browser API chain remains protected.
            .exceptionHandling(e->e.authenticationEntryPoint((req,res,error)->res.sendError(401)))
            .addFilterAfter(new LiveIdentityFilter(identities),SecurityContextHolderFilter.class)
            .addFilterBefore(new ProtocolThrottleFilter(throttle),SecurityContextHolderFilter.class);
        headers(http); return http.build();
    }
    @Bean JwtDecoder jwtDecoder(JWKSource<SecurityContext> keys,AuthorizationServerSettings settings) {
        JwtDecoder delegate=OAuth2AuthorizationServerConfiguration.jwtDecoder(keys);
        if(delegate instanceof NimbusJwtDecoder decoder) decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
            JwtValidators.createDefaultWithIssuer(settings.getIssuer()),
            new JwtClaimValidator<List<String>>("aud",aud->aud!=null && aud.contains("gatekeeper-resource"))));
        return delegate;
    }
    @Bean @Order(2) SecurityFilterChain resource(HttpSecurity http,OAuth2AuthorizationService authorizations,IdentityRepository identities) throws Exception {
        http.securityMatcher("/resource/**").sessionManagement(s->s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(csrf->csrf.disable()) // bearer-only chain, never reads a browser SecurityContext
            .securityContext(s->s.securityContextRepository(new org.springframework.security.web.context.NullSecurityContextRepository()))
            .authorizeHttpRequests(auth->auth.requestMatchers("/resource/me").hasAuthority("SCOPE_resource.read").anyRequest().denyAll())
            .oauth2ResourceServer(oauth->oauth.jwt(Customizer.withDefaults()))
            .addFilterAfter(new org.springframework.web.filter.OncePerRequestFilter(){
                @Override protected void doFilterInternal(jakarta.servlet.http.HttpServletRequest req,jakarta.servlet.http.HttpServletResponse res,jakarta.servlet.FilterChain chain) throws java.io.IOException,jakarta.servlet.ServletException {
                    var authentication=org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();
                    if(authentication instanceof org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken jwt) {
                        var saved=authorizations.findByToken(jwt.getToken().getTokenValue(),OAuth2TokenType.ACCESS_TOKEN);
                        Identity identity;
                        try{identity=identities.find(UUID.fromString(jwt.getName())).orElse(null);}catch(IllegalArgumentException e){identity=null;}
                        String version=jwt.getToken().getClaimAsString("cv");
                        if(saved==null || saved.getAccessToken()==null || !saved.getAccessToken().isActive() || identity==null || !identity.state().equals("ACTIVE") || !Long.toString(identity.credentialVersion()).equals(version)) {res.setStatus(401);return;}
                    }
                    chain.doFilter(req,res);
                }
            },org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter.class);
        headers(http);return http.build();
    }
    @Bean @Order(3) SecurityFilterChain browser(HttpSecurity http,IdentityRepository identities,AuditService audit,RevocationService revocation) throws Exception {
        http.authorizeHttpRequests(auth->auth
            .dispatcherTypeMatchers(jakarta.servlet.DispatcherType.ERROR).permitAll()
            .requestMatchers("/api/auth/csrf","/api/auth/login","/api/auth/mfa","/api/registration","/api/recovery/request","/api/recovery/reset","/actuator/health","/actuator/health/**").permitAll()
            .requestMatchers("/api/admin/**").hasAuthority("identity:manage")
            .requestMatchers("/api/audit").hasAuthority("audit:read")
            .requestMatchers("/actuator/prometheus").hasAuthority("metrics:read")
            .requestMatchers("/api/identities/*","/api/password","/api/mfa/**","/api/sessions/**").authenticated()
            .anyRequest().denyAll())
            .csrf(csrf->csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()))
            .requestCache(cache->cache.disable())
            .exceptionHandling(e->e.authenticationEntryPoint((req,res,error)->res.setStatus(401)))
            .sessionManagement(s->s.sessionFixation(f->f.changeSessionId()))
            .logout(logout->logout.logoutUrl("/api/auth/logout").addLogoutHandler((req,res,auth)->{
                if(auth!=null) {UUID id=UUID.fromString(auth.getName());revocation.all(id);audit.record(id,"LOGOUT","SUCCESS",id);}
            }).logoutSuccessHandler((req,res,auth)->res.setStatus(auth==null?401:204)).deleteCookies("SESSION"))
            .addFilterAfter(new LiveIdentityFilter(identities),SecurityContextHolderFilter.class);
        headers(http);return http.build();
    }
    private void headers(HttpSecurity http) throws Exception {
        http.headers(h->h.contentSecurityPolicy(c->c.policyDirectives("default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"))
            .referrerPolicy(r->r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)));
    }
}
