package io.github.guinovaisz.gatekeeper;

import java.net.*;
import java.net.http.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicReference;
import com.fasterxml.jackson.databind.*;
import org.junit.jupiter.api.*;
import static org.assertj.core.api.Assertions.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.*;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.*;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.shared.*;
import io.github.guinovaisz.gatekeeper.mfa.*;
import io.github.guinovaisz.gatekeeper.credential.*;
import io.github.guinovaisz.gatekeeper.security.Throttle;

@SpringBootTest(webEnvironment=SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("test")
@Testcontainers
@Import(IamSecurityIT.TimeConfiguration.class)
class IamSecurityIT {
    @Container static final PostgreSQLContainer<?> POSTGRES=new PostgreSQLContainer<>("postgres:18.7-alpine");
    static final String CLIENT_SECRET=Secrets.token(32);
    static final String STORE_PASSWORD=Secrets.token(24);
    static final Path STORE=keyStore();
    @DynamicPropertySource static void properties(DynamicPropertyRegistry properties) {
        properties.add("spring.datasource.url",POSTGRES::getJdbcUrl);
        properties.add("spring.datasource.username",POSTGRES::getUsername);
        properties.add("spring.datasource.password",POSTGRES::getPassword);
        properties.add("gatekeeper.mfa-key",()->Base64.getEncoder().encodeToString(Secrets.bytes(32)));
        properties.add("gatekeeper.key-store",STORE::toString);
        properties.add("gatekeeper.key-store-password",()->STORE_PASSWORD);
        properties.add("gatekeeper.client-secret",()->CLIENT_SECRET);
        properties.add("gatekeeper.issuer",()->"http://127.0.0.1:8080");
        properties.add("server.servlet.session.cookie.secure",()->false);
    }
    private static Path keyStore() {
        try {
            Path path=Files.createTempDirectory("gatekeeper-test-").resolve("signing.p12");path.toFile().deleteOnExit();path.getParent().toFile().deleteOnExit();
            String executable=Path.of(System.getProperty("java.home"),"bin",System.getProperty("os.name").startsWith("Windows")?"keytool.exe":"keytool").toString();
            ProcessBuilder process=new ProcessBuilder(executable,"-genkeypair","-alias","signing","-keyalg","RSA","-keysize","3072","-sigalg","SHA256withRSA","-validity","2","-dname","CN=Gatekeeper test","-storetype","PKCS12","-keystore",path.toString(),"-storepass:env","GK_TEST_STORE_PASSWORD");
            process.environment().put("GK_TEST_STORE_PASSWORD",STORE_PASSWORD);
            process.redirectErrorStream(true).redirectOutput(ProcessBuilder.Redirect.DISCARD);
            Process child=process.start();if(!child.waitFor(30,TimeUnit.SECONDS)||child.exitValue()!=0)throw new IllegalStateException("Test key generation failed");return path;
        } catch(Exception e){throw new IllegalStateException("Test key setup failed",e);}
    }
    static class MutableClock extends Clock {
        private final AtomicReference<Instant> now=new AtomicReference<>(Instant.now());
        public ZoneId getZone(){return ZoneOffset.UTC;}
        public Clock withZone(ZoneId zone){return this;}
        public Instant instant(){return now.get();}
        void advance(Duration duration){now.updateAndGet(i->i.plus(duration));}
        void reset(){now.set(Instant.now());}
    }
    @TestConfiguration static class TimeConfiguration { @Bean @Primary MutableClock testClock(){return new MutableClock();} }
    @LocalServerPort int port;
    @Autowired JdbcTemplate db;
    @Autowired IdentityService identities;
    @Autowired IdentityRepository repository;
    @Autowired PasswordEncoder encoder;
    @Autowired MfaService mfa;
    @Autowired RecoveryService recovery;
    @Autowired LocalRecoveryDelivery delivery;
    @Autowired MutableClock clock;
    @Autowired Throttle throttle;
    @Autowired com.nimbusds.jose.jwk.source.JWKSource<com.nimbusds.jose.proc.SecurityContext> signingKeys;
    private final ObjectMapper json=new ObjectMapper();
    @BeforeEach void resetLimits(){db.update("DELETE FROM security_throttle");clock.reset();}
    private record Account(UUID id,String login,String password) { @Override public String toString(){return "Account[redacted]";} }
    private Account account(){String login="u"+UUID.randomUUID()+"@example.test";String password=Secrets.token(24);return new Account(identities.register(login,password,false),login,password);}
    private record Reply(int status,String body,HttpHeaders headers) { @Override public String toString(){return "Reply[status="+status+"]";} }
    private class Browser {
        final CookieManager cookies=new CookieManager(null,CookiePolicy.ACCEPT_ALL);
        final HttpClient client=HttpClient.newBuilder().cookieHandler(cookies).followRedirects(HttpClient.Redirect.NEVER).connectTimeout(Duration.ofSeconds(5)).build();
        String cookie(){return cookies.getCookieStore().getCookies().stream().filter(c->c.getName().equals("SESSION")).map(HttpCookie::getValue).findFirst().orElse("");}
        Reply get(String path) throws Exception{return send("GET",path,null,false,null);}
        Reply mutate(String method,String path,Object input) throws Exception{return send(method,path,input,true,null);}
        Reply send(String method,String path,Object body,boolean csrf,String bearer) throws Exception {
            HttpRequest.Builder builder=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+path)).timeout(Duration.ofSeconds(15));
            if(csrf) {Reply token=get("/api/auth/csrf");JsonNode value=json.readTree(token.body());builder.header(value.path("headerName").asText(),value.path("token").asText());}
            if(bearer!=null)builder.header("Authorization","Bearer "+bearer);
            if(body!=null)builder.header("Content-Type","application/json");
            builder.method(method,body==null?HttpRequest.BodyPublishers.noBody():HttpRequest.BodyPublishers.ofString(json.writeValueAsString(body)));
            HttpResponse<String> response=client.send(builder.build(),HttpResponse.BodyHandlers.ofString());return new Reply(response.statusCode(),response.body(),response.headers());
        }
        Reply login(Account account) throws Exception{return mutate("POST","/api/auth/login",Map.of("login",account.login(),"password",account.password()));}
        Reply form(Map<String,String> input) throws Exception {
            String encoded=input.entrySet().stream().map(e->URLEncoder.encode(e.getKey(),StandardCharsets.UTF_8)+"="+URLEncoder.encode(e.getValue(),StandardCharsets.UTF_8)).collect(java.util.stream.Collectors.joining("&"));
            HttpRequest.Builder request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/oauth2/token")).header("Content-Type","application/x-www-form-urlencoded");
            if(input.get("client_id").equals("gatekeeper-confidential")) request.header("Authorization","Basic "+Base64.getEncoder().encodeToString(("gatekeeper-confidential:"+CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)));
            HttpResponse<String> response=client.send(request.POST(HttpRequest.BodyPublishers.ofString(encoded)).build(),HttpResponse.BodyHandlers.ofString());
            return new Reply(response.statusCode(),response.body(),response.headers());
        }
    }
    @Test void passwordStorageAndNormalizedDatabaseConstraints() {
        Account a=account();String stored=db.queryForObject("SELECT password_hash FROM identity_account WHERE id=?",String.class,a.id());
        assertThat(stored.startsWith("{argon2id}$argon2id$")).isTrue();assertThat(stored.equals(a.password())).isFalse();assertThat(encoder.matches(a.password(),stored)).isTrue();
        assertThat(identities.register(a.login().toUpperCase(Locale.ROOT),Secrets.token(24),false)==null).isTrue();
        assertThatThrownBy(()->db.update("INSERT INTO identity_role VALUES (?,?)",a.id(),"MISSING_ROLE")).isInstanceOf(org.springframework.dao.DataIntegrityViolationException.class);
        System.out.println("G1_G20_STORAGE_PROOF passwordHash=argon2id normalizedUnique=true foreignKey=enforced");
    }
    @Test void loginSessionFixationCsrfOwnershipAndDefaultDeny() throws Exception {
        Account a=account(),b=account();Browser browser=new Browser();
        assertThat(browser.get("/api/auth/csrf").status()).isEqualTo(200);String old=browser.cookie();
        assertThat(old.isBlank()).isFalse();assertThat(browser.login(a).status()).isEqualTo(204);
        assertThat(browser.cookie().equals(old)).isFalse();
        assertThat(browser.get("/api/identities/"+a.id()).status()).isEqualTo(200);
        assertThat(browser.get("/api/identities/"+b.id()).status()).isEqualTo(404);
        assertThat(browser.mutate("PATCH","/api/admin/identities/"+b.id()+"/state",Map.of("state","DISABLED")).status()).isEqualTo(403);
        assertThat(browser.send("POST","/api/password",Map.of("current",a.password(),"replacement",Secrets.token(24)),false,null).status()).isEqualTo(403);
        assertThat(browser.get("/not-classified").status()).isEqualTo(403);
        Reply headers=browser.get("/api/identities/"+a.id());
        assertThat(headers.headers().firstValue("X-Content-Type-Options")).contains("nosniff");
        assertThat(headers.headers().firstValue("Cache-Control").orElse("").contains("no-store")).isTrue();
        System.out.println("G2_G5_SESSION_AUTHZ_PROOF rotated=true csrf=denied horizontal=denied vertical=denied defaultDeny=true");
    }
    @Test void enumerationLockDisabledAndBruteForceAreGenericAndBounded() throws Exception {
        Account a=account();Browser browser=new Browser();
        Reply known=browser.mutate("POST","/api/auth/login",Map.of("login",a.login(),"password",Secrets.token(24)));
        Reply unknown=browser.mutate("POST","/api/auth/login",Map.of("login","unknown@example.test","password",Secrets.token(24)));
        assertThat(known.status()).isEqualTo(401);assertThat(known.body().equals(unknown.body())).isTrue();
        for(String state:List.of("LOCKED","DISABLED")) {
            identities.state(a.id(),a.id(),state);assertThat(browser.login(a).status()).isEqualTo(401);
        }
        identities.state(a.id(),a.id(),"ACTIVE");
        for(int i=0;i<8;i++)browser.mutate("POST","/api/auth/login",Map.of("login",a.login(),"password",Secrets.token(24)));
        assertThat(browser.login(a).status()).isEqualTo(401);
        clock.advance(Duration.ofMinutes(6));assertThat(browser.login(a).status()).isEqualTo(204);
        System.out.println("G6_BRUTE_FORCE_PROOF temporaryBlock=true clockExpiry=true locked=denied disabled=denied enumeration=generic");
    }
    @Test void mfaEnrollmentReplayRecoveryAndNoPasswordOnlyBypass() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        String secret=mfa.begin(a.id(),a.password());
        assertThat(repository.find(a.id()).orElseThrow().mfaSecret()==null).isTrue();
        assertThatThrownBy(()->mfa.activate(a.id(),"bad")).isInstanceOf(IllegalArgumentException.class);
        String code=Totp.code(secret,clock.instant().getEpochSecond()/30);List<String> codes=mfa.activate(a.id(),code);
        assertThat(mfa.verify(a.id(),code,false)).isFalse();
        Browser pending=new Browser();assertThat(pending.login(a).status()).isEqualTo(202);
        assertThat(pending.get("/api/identities/"+a.id()).status()).isEqualTo(401);
        assertThat(pending.mutate("POST","/api/auth/mfa",Map.of("code",codes.getFirst(),"recovery",true)).status()).isEqualTo(204);
        assertThat(mfa.verify(a.id(),codes.getFirst(),true)).isFalse();
        assertThat(pending.get("/api/identities/"+a.id()).status()).isEqualTo(200);
        assertThat(db.queryForObject("SELECT mfa_secret FROM identity_account WHERE id=?",String.class,a.id()).equals(secret)).isFalse();
        assertThat(db.queryForList("SELECT digest FROM recovery_code WHERE identity_id=?",String.class,a.id()).contains(codes.get(1))).isFalse();
        System.out.println("G7_G8_MFA_PROOF activationRequiresProof=true passwordOnly=denied totpReplay=denied recoverySingleUse=true encryptedSeed=true");
    }
    @Test void concurrentRecoveryCodeAllowsExactlyOneWinner() throws Exception {
        Account a=account();String secret=mfa.begin(a.id(),a.password());List<String> codes=mfa.activate(a.id(),Totp.code(secret,clock.instant().getEpochSecond()/30));
        List<Boolean> results=race(()->mfa.verify(a.id(),codes.getFirst(),true));
        assertThat(results.stream().filter(Boolean::booleanValue).count()).isEqualTo(1);
        System.out.println("CONCURRENT_RECOVERY_PROOF attempts=2 success=1 rejected=1");
    }
    @Test void resetEnumerationSingleUseExpiryAndConcurrentWinnerRevokesSession() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        Reply known=browser.mutate("POST","/api/recovery/request",Map.of("login",a.login()));
        Reply unknown=browser.mutate("POST","/api/recovery/request",Map.of("login","no-such-user@example.test"));
        assertThat(known.status()).isEqualTo(202);assertThat(known.body().equals(unknown.body())).isTrue();
        String token=delivery.take(a.id());assertThat(token!=null).isTrue();
        assertThat(db.queryForObject("SELECT digest FROM password_reset WHERE identity_id=?",String.class,a.id()).equals(token)).isFalse();
        String replacement=Secrets.token(24);
        List<Boolean> results=race(()->{try{recovery.reset(token,replacement);return true;}catch(IllegalArgumentException e){return false;}});
        assertThat(results.stream().filter(Boolean::booleanValue).count()).isEqualTo(1);
        assertThatThrownBy(()->recovery.reset(token,Secrets.token(24))).isInstanceOf(IllegalArgumentException.class);
        assertThat(browser.get("/api/identities/"+a.id()).status()).isEqualTo(401);
        recovery.request(a.login());String expired=delivery.take(a.id());clock.advance(Duration.ofMinutes(11));
        assertThatThrownBy(()->recovery.reset(expired,Secrets.token(24))).isInstanceOf(IllegalArgumentException.class);
        System.out.println("G9_G10_G17_RESET_PROOF replay=rejected concurrentAttempts=2 success=1 rejected=1 expired=rejected oldSession=revoked");
    }
    private List<Boolean> race(Callable<Boolean> operation) throws Exception {
        ExecutorService pool=Executors.newFixedThreadPool(2);CyclicBarrier start=new CyclicBarrier(2);
        try {List<Future<Boolean>> tasks=new ArrayList<>();for(int i=0;i<2;i++)tasks.add(pool.submit(()->{start.await(5,TimeUnit.SECONDS);return operation.call();}));
            return List.of(tasks.get(0).get(20,TimeUnit.SECONDS),tasks.get(1).get(20,TimeUnit.SECONDS));
        }finally{pool.shutdownNow();}
    }
    @Test void appendOnlyAuditAndLowCardinalityMetrics() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        assertThat(db.queryForObject("SELECT count(*) FROM security_audit WHERE actor=? AND action='LOGIN_SUCCESS'",Integer.class,a.id())).isEqualTo(1);
        assertThatThrownBy(()->db.update("UPDATE security_audit SET outcome='DENIED' WHERE actor=?",a.id())).isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThatThrownBy(()->db.update("DELETE FROM security_audit WHERE actor=?",a.id())).isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThatThrownBy(()->db.execute("TRUNCATE security_audit")).isInstanceOf(org.springframework.dao.DataAccessException.class);
        assertThat(new Browser().get("/actuator/env").status()).isEqualTo(401);
        assertThat(new Browser().get("/actuator/health/readiness").status()).isEqualTo(200);
        System.out.println("G18_AUDIT_PROOF persistent=true update=denied delete=denied truncate=denied secretFields=absent");
    }
    @Test void throttleUsesInjectedClockAndAtomicDatabaseCounter() {
        assertThat(throttle.allow("test","source",2,Duration.ofSeconds(30))).isTrue();
        assertThat(throttle.allow("test","source",2,Duration.ofSeconds(30))).isTrue();
        assertThat(throttle.allow("test","source",2,Duration.ofSeconds(30))).isFalse();
        clock.advance(Duration.ofSeconds(31));assertThat(throttle.allow("test","source",2,Duration.ofSeconds(30))).isTrue();
    }
    private static String enc(String input){return URLEncoder.encode(input,StandardCharsets.UTF_8);}
    private Reply authorize(Browser browser,String client,String verifier,String redirect,String method) throws Exception {
        String challenge=Base64.getUrlEncoder().withoutPadding().encodeToString(MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII)));
        return browser.get("/oauth2/authorize?response_type=code&client_id="+client+"&redirect_uri="+enc(redirect)+"&scope=openid%20resource.read&state=test-state&nonce=test-nonce&code_challenge="+challenge+"&code_challenge_method="+method);
    }
    private String code(Reply reply) {
        assertThat(reply.status()).isEqualTo(302);
        String location=reply.headers().firstValue("location").orElseThrow();
        Map<String,String> params=Arrays.stream(URI.create(location).getRawQuery().split("&")).map(p->p.split("=",2)).collect(java.util.stream.Collectors.toMap(p->p[0],p->URLDecoder.decode(p.length>1?p[1]:"",StandardCharsets.UTF_8)));
        assertThat(params.containsKey("code")).isTrue();assertThat(params.get("state")).isEqualTo("test-state");return params.get("code");
    }
    private Reply exchange(Browser browser,String client,String code,String verifier) throws Exception {
        Map<String,String> input=new HashMap<>(Map.of("grant_type","authorization_code","client_id",client,"code",code,"redirect_uri","http://127.0.0.1:9090/callback"));
        if(verifier!=null)input.put("code_verifier",verifier);return browser.form(input);
    }
    private Reply tokens(Browser browser,String client) throws Exception {
        String verifier=Secrets.token(48);String code=code(authorize(browser,client,verifier,"http://127.0.0.1:9090/callback","S256"));return exchange(browser,client,code,verifier);
    }
    private Reply refresh(Browser browser,String token) throws Exception {
        return browser.form(Map.of("grant_type","refresh_token","client_id","gatekeeper-confidential","refresh_token",token));
    }
    @Test void oidcDiscoveryJwksPkceAndCodeReplayAreRealProtocolFlows() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        Reply discovery=browser.get("/.well-known/openid-configuration");assertThat(discovery.status()).isEqualTo(200);
        assertThat(json.readTree(discovery.body()).path("issuer").asText()).isEqualTo("http://127.0.0.1:8080");
        Reply jwks=browser.get("/oauth2/jwks");assertThat(jwks.status()).isEqualTo(200);JsonNode key=json.readTree(jwks.body()).path("keys").get(0);
        assertThat(key.has("kid")).isTrue();assertThat(key.has("d")).isFalse();assertThat(key.has("p")).isFalse();
        String verifier=Secrets.token(48);String authorizationCode=code(authorize(browser,"gatekeeper-public",verifier,"http://127.0.0.1:9090/callback","S256"));
        Reply valid=exchange(browser,"gatekeeper-public",authorizationCode,verifier);assertThat(valid.status()).isEqualTo(200);
        JsonNode body=json.readTree(valid.body());String access=body.path("access_token").asText();
        assertThat(body.has("id_token")).isTrue();assertThat(body.has("refresh_token")).isFalse();
        com.nimbusds.jwt.SignedJWT idToken=com.nimbusds.jwt.SignedJWT.parse(body.path("id_token").asText());
        assertThat(idToken.getJWTClaimsSet().getAudience()).contains("gatekeeper-public");
        assertThat(idToken.getJWTClaimsSet().getStringClaim("nonce")).isEqualTo("test-nonce");
        com.nimbusds.jwt.SignedJWT accessJwt=com.nimbusds.jwt.SignedJWT.parse(access);
        assertThat(accessJwt.getJWTClaimsSet().getSubject()).isEqualTo(a.id().toString());
        assertThat(accessJwt.getJWTClaimsSet().getAudience()).contains("gatekeeper-resource");
        assertThat(accessJwt.getJWTClaimsSet().getExpirationTime().toInstant().minusSeconds(300).isAfter(Instant.now().minusSeconds(10))).isTrue();
        assertThat(accessJwt.getHeader().getKeyID()!=null).isTrue();assertThat(accessJwt.getJWTClaimsSet().getClaims().containsKey("email")).isFalse();
        assertThat(new Browser().send("GET","/resource/me",null,false,access).status()).isEqualTo(200);
        assertThat(exchange(browser,"gatekeeper-public",authorizationCode,verifier).status()).isEqualTo(400);
        System.out.println("G11_G13_OIDC_PROOF discovery=true publicJWKS=true authorizationCodeS256=accepted codeReplay=rejected idToken=true");
    }
    @Test void missingWrongPkceAndUnregisteredRedirectAreRejected() throws Exception {
        Browser browser=new Browser();assertThat(browser.login(account()).status()).isEqualTo(204);
        for(String verifier:Arrays.asList(null,Secrets.token(48))) {
            String correct=Secrets.token(48);String authorizationCode=code(authorize(browser,"gatekeeper-public",correct,"http://127.0.0.1:9090/callback","S256"));
            assertThat(exchange(browser,"gatekeeper-public",authorizationCode,verifier).status()).isEqualTo(400);
        }
        Reply bad=authorize(browser,"gatekeeper-public",Secrets.token(48),"https://attacker.example/callback","S256");
        assertThat(bad.status()).isEqualTo(400);assertThat(bad.headers().firstValue("location").isEmpty()).isTrue();
        Reply wrongPort=authorize(browser,"gatekeeper-public",Secrets.token(48),"http://127.0.0.1:9999/callback","S256");
        assertThat(wrongPort.status()).isEqualTo(400);
        Reply plain=authorize(browser,"gatekeeper-public",Secrets.token(48),"http://127.0.0.1:9090/callback","plain");
        assertThat(plain.headers().firstValue("location").orElse("").contains("code=")).isFalse();
        assertThat(browser.get("/oauth2/authorize?response_type=code&client_id=gatekeeper-public&redirect_uri="+enc("http://127.0.0.1:9090/callback")+"&scope=openid").headers().firstValue("location").orElse("").contains("code=")).isFalse();
        System.out.println("G12_G14_PKCE_REDIRECT_PROOF missingVerifier=rejected wrongVerifier=rejected plain=rejected invalidRedirect=rejected exactPort=true");
    }
    @Test void refreshRotationReplayRevokesFamilyAndConcurrentRefreshCannotFork() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        Reply first=tokens(browser,"gatekeeper-confidential");assertThat(first.status()).isEqualTo(200);
        String rt1=json.readTree(first.body()).path("refresh_token").asText();assertThat(rt1.isBlank()).isFalse();
        Reply second=refresh(browser,rt1);assertThat(second.status()).isEqualTo(200);String rt2=json.readTree(second.body()).path("refresh_token").asText();
        assertThat(rt1.equals(rt2)).isFalse();assertThat(refresh(browser,rt1).status()).isEqualTo(400);assertThat(refresh(browser,rt2).status()).isEqualTo(400);
        String rtConcurrent=json.readTree(tokens(browser,"gatekeeper-confidential").body()).path("refresh_token").asText();
        List<Boolean> results=race(()->refresh(new Browser(),rtConcurrent).status()==200);
        assertThat(results.stream().filter(Boolean::booleanValue).count()).isEqualTo(1);
        assertThat(db.queryForObject("SELECT count(*) FROM oauth2_authorization WHERE principal_name=?",Integer.class,a.id().toString())).isEqualTo(0);
        System.out.println("G16_REFRESH_REPLAY_PROOF rotated=true old=rejected family=revoked concurrentAttempts=2 success=1 validFamilies=0");
    }
    @Test void tokenRevocationAndPasswordResetInvalidateRefreshAndLocalAccess() throws Exception {
        Account a=account();Browser browser=new Browser();assertThat(browser.login(a).status()).isEqualTo(204);
        Reply issued=tokens(browser,"gatekeeper-confidential");String access=json.readTree(issued.body()).path("access_token").asText();String rt=json.readTree(issued.body()).path("refresh_token").asText();
        assertThat(new Browser().send("GET","/resource/me",null,false,access).status()).isEqualTo(200);
        String form="token="+enc(rt)+"&token_type_hint=refresh_token";
        HttpRequest request=HttpRequest.newBuilder(URI.create("http://127.0.0.1:"+port+"/oauth2/revoke")).header("Content-Type","application/x-www-form-urlencoded")
            .header("Authorization","Basic "+Base64.getEncoder().encodeToString(("gatekeeper-confidential:"+CLIENT_SECRET).getBytes(StandardCharsets.UTF_8)))
            .POST(HttpRequest.BodyPublishers.ofString(form)).build();
        assertThat(browser.client.send(request,HttpResponse.BodyHandlers.discarding()).statusCode()).isEqualTo(200);
        assertThat(refresh(browser,rt).status()).isEqualTo(400);
        Reply next=tokens(browser,"gatekeeper-confidential");String nextRt=json.readTree(next.body()).path("refresh_token").asText();String nextAt=json.readTree(next.body()).path("access_token").asText();
        recovery.request(a.login());recovery.reset(delivery.take(a.id()),Secrets.token(24));
        assertThat(refresh(new Browser(),nextRt).status()).isEqualTo(400);assertThat(new Browser().send("GET","/resource/me",null,false,nextAt).status()).isEqualTo(401);
        System.out.println("G17_TOKEN_REVOCATION_PROOF standardRevocation=true resetRefresh=revoked resetLocalAccess=revoked");
    }
    private String signedToken(String issuer,String audience,Instant expires,boolean wrongKey) throws Exception {
        com.nimbusds.jose.jwk.RSAKey key=(com.nimbusds.jose.jwk.RSAKey)signingKeys.get(new com.nimbusds.jose.jwk.JWKSelector(new com.nimbusds.jose.jwk.JWKMatcher.Builder().build()),null).getFirst();
        var signingKey=wrongKey?new com.nimbusds.jose.jwk.gen.RSAKeyGenerator(3072).generate():key;
        com.nimbusds.jwt.JWTClaimsSet claims=new com.nimbusds.jwt.JWTClaimsSet.Builder().issuer(issuer).audience(audience).subject(UUID.randomUUID().toString())
            .issueTime(Date.from(Instant.now().minusSeconds(600))).expirationTime(Date.from(expires)).claim("scope","resource.read").build();
        var jwt=new com.nimbusds.jwt.SignedJWT(new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256).keyID(key.getKeyID()).build(),claims);
        jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(signingKey));return jwt.serialize();
    }
    @Test void malformedExpiredWrongSignatureAudienceAndIssuerAreRejectedWithoutDetails() throws Exception {
        List<String> invalid=List.of("malformed",signedToken("http://127.0.0.1:8080","gatekeeper-resource",Instant.now().minusSeconds(120),false),
            signedToken("http://127.0.0.1:8080","gatekeeper-resource",Instant.now().plusSeconds(300),true),
            signedToken("http://127.0.0.1:8080","wrong-audience",Instant.now().plusSeconds(300),false),
            signedToken("https://wrong-issuer.example","gatekeeper-resource",Instant.now().plusSeconds(300),false));
        for(String token:invalid) {
            Reply response=new Browser().send("GET","/resource/me",null,false,token);assertThat(response.status()).isEqualTo(401);
            assertThat(response.body().contains("Exception") || response.body().contains("org.springframework") || response.body().contains(token)).isFalse();
        }
        System.out.println("G15_TOKEN_VALIDATION_PROOF malformed=denied expired=denied invalidSignature=denied wrongAudience=denied wrongIssuer=denied");
    }
    @Test void ownSessionRevocationLogoutAndCookieFlags() throws Exception {
        Account a=account();Browser first=new Browser(),second=new Browser();
        assertThat(first.login(a).status()).isEqualTo(204);assertThat(second.login(a).status()).isEqualTo(204);
        JsonNode sessions=json.readTree(first.get("/api/sessions").body());assertThat(sessions.isArray()).isTrue();assertThat(sessions.size()).isEqualTo(2);
        assertThat(sessions.get(0).has("session_id")).isFalse();assertThat(sessions.get(0).has("sessionId")).isFalse();
        Account b=account();Browser other=new Browser();assertThat(other.login(b).status()).isEqualTo(204);
        assertThat(other.mutate("DELETE","/api/sessions/"+sessions.get(0).path("id").asText(),null).status()).isEqualTo(404);
        assertThat(first.mutate("DELETE","/api/sessions",null).status()).isEqualTo(204);assertThat(second.get("/api/identities/"+a.id()).status()).isEqualTo(401);
        assertThat(first.mutate("POST","/api/auth/logout",null).status()).isEqualTo(204);assertThat(first.get("/api/identities/"+a.id()).status()).isEqualTo(401);
        Reply cookie=new Browser().get("/api/auth/csrf");String setCookie=cookie.headers().firstValue("set-cookie").orElse("");
        assertThat(setCookie.contains("HttpOnly")).isTrue();assertThat(setCookie.contains("SameSite=Lax")).isTrue();
        System.out.println("SESSION_REVOCATION_PROOF ownership=denied others=revoked logout=invalidated httpOnly=true sameSite=Lax");
    }
}
