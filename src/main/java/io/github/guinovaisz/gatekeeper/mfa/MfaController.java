package io.github.guinovaisz.gatekeeper.mfa;

import java.time.Duration;
import java.util.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.security.core.Authentication;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import io.github.guinovaisz.gatekeeper.security.Throttle;

@RestController
@RequestMapping("/api/mfa")
public class MfaController {
    public record Proof(@NotBlank @Size(max=256) String password,@Size(max=6) String code) { @Override public String toString(){return "Proof[redacted]";} }
    private final MfaService service; private final Throttle throttle;
    public MfaController(MfaService service,Throttle throttle){this.service=service;this.throttle=throttle;}
    @PostMapping("/enrollment") public Map<String,String> begin(@Valid @RequestBody Proof proof,Authentication auth) {
        limit(auth);String secret=service.begin(UUID.fromString(auth.getName()),proof.password());
        return Map.of("secret",secret,"uri","otpauth://totp/Gatekeeper:"+auth.getName()+"?secret="+secret+"&issuer=Gatekeeper&algorithm=SHA1&digits=6&period=30");
    }
    @PostMapping("/activation") public Map<String,Object> activate(@RequestBody Map<String,String> proof,Authentication auth,HttpServletRequest request) {
        limit(auth);List<String> codes=service.activate(UUID.fromString(auth.getName()),proof.get("code"));request.getSession().invalidate();return Map.of("recoveryCodes",codes);
    }
    @PostMapping("/recovery-codes") public Map<String,Object> regenerate(@Valid @RequestBody Proof proof,Authentication auth) {
        limit(auth);return Map.of("recoveryCodes",service.regenerate(UUID.fromString(auth.getName()),proof.password(),proof.code()));
    }
    @DeleteMapping public ResponseEntity<Void> disable(@Valid @RequestBody Proof proof,Authentication auth,HttpServletRequest request) {
        limit(auth);service.disable(UUID.fromString(auth.getName()),proof.password(),proof.code());request.getSession().invalidate();return ResponseEntity.noContent().build();
    }
    private void limit(Authentication auth) {if(!throttle.allow("mfa-management",auth.getName(),10,Duration.ofMinutes(5))) throw new ResponseStatusException(HttpStatus.TOO_MANY_REQUESTS);}
}
