package io.github.guinovaisz.gatekeeper.session;

import java.util.*;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import io.github.guinovaisz.gatekeeper.audit.AuditService;

@RestController
@RequestMapping("/api/sessions")
public class SessionController {
    private final JdbcTemplate db;private final AuditService audit;
    public SessionController(JdbcTemplate db,AuditService audit){this.db=db;this.audit=audit;}
    @GetMapping public List<Map<String,Object>> list(Authentication auth) {
        // PRIMARY_ID is a management handle, never SESSION_ID (the bearer credential).
        return db.query("SELECT primary_id,creation_time,last_access_time FROM spring_session WHERE principal_name=?",(r,n)->Map.of("id",r.getString(1),"createdAt",r.getLong(2),"lastAccessAt",r.getLong(3)),auth.getName());
    }
    @DeleteMapping("/{id}") public ResponseEntity<Void> revoke(@PathVariable String id,Authentication auth) {
        int changed=db.update("DELETE FROM spring_session WHERE primary_id=? AND principal_name=?",id,auth.getName());
        if(changed==0) throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        audit.record(UUID.fromString(auth.getName()),"SESSION_REVOKED","SUCCESS",UUID.fromString(auth.getName()));return ResponseEntity.noContent().build();
    }
    @DeleteMapping public ResponseEntity<Void> others(Authentication auth,HttpServletRequest request) {
        db.update("DELETE FROM spring_session WHERE principal_name=? AND session_id<>?",auth.getName(),request.getSession().getId());
        audit.record(UUID.fromString(auth.getName()),"OTHER_SESSIONS_REVOKED","SUCCESS",UUID.fromString(auth.getName()));return ResponseEntity.noContent().build();
    }
}
