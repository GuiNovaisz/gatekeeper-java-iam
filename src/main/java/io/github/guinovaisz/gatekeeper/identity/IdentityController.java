package io.github.guinovaisz.gatekeeper.identity;

import java.time.Duration;
import java.util.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.*;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import io.github.guinovaisz.gatekeeper.authentication.AuthenticationController.Login;
import io.github.guinovaisz.gatekeeper.credential.RecoveryService;
import io.github.guinovaisz.gatekeeper.security.Throttle;

@RestController
public class IdentityController {
    public record ResetRequest(@NotBlank @Size(max=254) String login) {}
    public record Reset(@NotBlank @Size(max=128) String token,@NotBlank @Size(max=256) String password) { @Override public String toString(){return "Reset[redacted]";} }
    public record PasswordChange(@NotBlank @Size(max=256) String current,@NotBlank @Size(max=256) String replacement) { @Override public String toString(){return "PasswordChange[redacted]";} }
    public record State(@Pattern(regexp="ACTIVE|LOCKED|DISABLED") @NotNull String state) {}
    private final IdentityService service; private final IdentityRepository identities; private final RecoveryService recovery; private final Throttle throttle;
    public IdentityController(IdentityService service,IdentityRepository identities,RecoveryService recovery,Throttle throttle) {this.service=service;this.identities=identities;this.recovery=recovery;this.throttle=throttle;}
    @PostMapping("/api/registration") public ResponseEntity<Void> register(@Valid @RequestBody Login input,HttpServletRequest request) {
        limit("registration",request.getRemoteAddr(),5); service.register(input.login(),input.password(),false); return ResponseEntity.accepted().build();
    }
    @GetMapping("/api/identities/{id}") @PreAuthorize("hasAuthority('identity:read')")
    public Map<String,Object> own(@PathVariable UUID id,Authentication auth) {
        if(!auth.getName().equals(id.toString())) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        Identity identity=identities.find(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND));
        return Map.of("id",id,"state",identity.state(),"mfaEnabled",identity.mfaSecret()!=null);
    }
    @PostMapping("/api/password") public ResponseEntity<Void> password(@Valid @RequestBody PasswordChange input,Authentication auth,HttpServletRequest request) {
        limit("password",auth.getName(),5);service.changePassword(UUID.fromString(auth.getName()),input.current(),input.replacement()); request.getSession().invalidate();return ResponseEntity.noContent().build();
    }
    @PostMapping("/api/recovery/request") public ResponseEntity<Void> request(@Valid @RequestBody ResetRequest input,HttpServletRequest request) {
        limit("recovery-source",request.getRemoteAddr(),10);limit("recovery-account",IdentityRepository.normalize(input.login()),3);
        recovery.request(input.login());return ResponseEntity.accepted().build();
    }
    @PostMapping("/api/recovery/reset") public ResponseEntity<Void> reset(@Valid @RequestBody Reset input,HttpServletRequest request) {
        limit("reset-source",request.getRemoteAddr(),10);recovery.reset(input.token(),input.password());return ResponseEntity.noContent().build();
    }
    @PatchMapping("/api/admin/identities/{id}/state") @PreAuthorize("hasAuthority('identity:manage')")
    public ResponseEntity<Void> state(@PathVariable UUID id,@Valid @RequestBody State input,Authentication auth) {
        service.state(UUID.fromString(auth.getName()),id,input.state());return ResponseEntity.noContent().build();
    }
    private void limit(String kind,String key,int max) {if(!throttle.allow(kind,key,max,Duration.ofMinutes(5))) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);}
}
