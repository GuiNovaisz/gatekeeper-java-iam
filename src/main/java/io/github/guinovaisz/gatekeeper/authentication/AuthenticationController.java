package io.github.guinovaisz.gatekeeper.authentication;

import java.time.*;
import java.util.*;
import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.*;
import org.springframework.security.core.context.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.*;
import io.github.guinovaisz.gatekeeper.identity.*;
import io.github.guinovaisz.gatekeeper.audit.AuditService;
import io.github.guinovaisz.gatekeeper.mfa.MfaService;
import io.github.guinovaisz.gatekeeper.security.Throttle;

@RestController
@RequestMapping("/api/auth")
public class AuthenticationController {
    public record Login(@NotBlank @Size(max=254) String login,@NotBlank @Size(max=256) String password) { @Override public String toString(){return "Login[redacted]";} }
    public record Challenge(@NotBlank @Size(max=128) String code,boolean recovery) { @Override public String toString(){return "Challenge[redacted]";} }
    private final LocalAuthentication local; private final IdentityRepository identities; private final MfaService mfa;
    private final Throttle throttle; private final Clock clock; private final AuditService audit;
    public AuthenticationController(LocalAuthentication local,IdentityRepository identities,MfaService mfa,Throttle throttle,Clock clock,AuditService audit) {
        this.local=local;this.identities=identities;this.mfa=mfa;this.throttle=throttle;this.clock=clock;this.audit=audit;
    }
    @GetMapping("/csrf") public Map<String,String> csrf(CsrfToken csrf) {return Map.of("headerName",csrf.getHeaderName(),"token",csrf.getToken());}
    @PostMapping("/login") public ResponseEntity<?> login(@Valid @RequestBody Login input,HttpServletRequest request,HttpServletResponse response) {
        Identity identity=local.password(input.login(),input.password(),request.getRemoteAddr());
        // Drop an existing context before starting a different authentication.
        SecurityContextHolder.clearContext();
        request.getSession().removeAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        request.changeSessionId();
        if(identity.mfaSecret()!=null) {
            request.getSession().setAttribute("pending",identity.id().toString());
            request.getSession().setAttribute("pendingVersion",identity.credentialVersion());
            request.getSession().setAttribute("pendingUntil",clock.instant().plusSeconds(180).getEpochSecond());
            return ResponseEntity.status(202).body(Map.of("status","MFA_REQUIRED"));
        }
        complete(identity,request,response);
        return ResponseEntity.noContent().build();
    }
    @PostMapping("/mfa") public ResponseEntity<Void> challenge(@Valid @RequestBody Challenge input,HttpServletRequest request,HttpServletResponse response) {
        HttpSession session=request.getSession(false);
        if(session==null || session.getAttribute("pending")==null || clock.instant().getEpochSecond()> (Long)session.getAttribute("pendingUntil")) throw new BadCredentialsException("Authentication rejected");
        UUID id=UUID.fromString((String)session.getAttribute("pending"));
        if(!throttle.allow("mfa",id.toString(),5,Duration.ofMinutes(5)) || !throttle.allow("mfa-source",request.getRemoteAddr(),30,Duration.ofMinutes(5))) throw new BadCredentialsException("Authentication rejected");
        Identity identity=identities.find(id).orElseThrow(()->new BadCredentialsException("Authentication rejected"));
        if(identity.credentialVersion()!=(Long)session.getAttribute("pendingVersion") || !mfa.verify(id,input.code(),input.recovery())) throw new BadCredentialsException("Authentication rejected");
        complete(identity,request,response); return ResponseEntity.noContent().build();
    }
    private void complete(Identity identity,HttpServletRequest request,HttpServletResponse response) {
        HttpSession session=request.getSession(); request.changeSessionId();
        new org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository().saveToken(null,request,response);
        session.removeAttribute("pending");session.removeAttribute("pendingUntil");session.removeAttribute("pendingVersion");
        session.setAttribute("credentialVersion",identity.credentialVersion());
        List<org.springframework.security.core.GrantedAuthority> authorities=new ArrayList<>(identities.permissions(identity.id()).stream().map(SimpleGrantedAuthority::new).toList());
        authorities.add(org.springframework.security.core.authority.FactorGrantedAuthority.fromAuthority(org.springframework.security.core.authority.FactorGrantedAuthority.PASSWORD_AUTHORITY));
        User principal=new User(identity.id().toString(),"",authorities);
        Authentication auth=UsernamePasswordAuthenticationToken.authenticated(principal,null,principal.getAuthorities());
        SecurityContext context=SecurityContextHolder.createEmptyContext(); context.setAuthentication(auth); SecurityContextHolder.setContext(context);
        new HttpSessionSecurityContextRepository().saveContext(context,request,response);
        audit.record(identity.id(),"LOGIN_SUCCESS","SUCCESS",identity.id());
    }
}
