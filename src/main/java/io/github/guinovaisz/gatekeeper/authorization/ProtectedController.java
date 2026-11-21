package io.github.guinovaisz.gatekeeper.authorization;

import java.util.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
public class ProtectedController {
    private final JdbcTemplate db;
    public ProtectedController(JdbcTemplate db){this.db=db;}
    @GetMapping("/resource/me") public Map<String,String> resource(Authentication authentication){return Map.of("subject",authentication.getName());}
    @GetMapping("/api/audit") @PreAuthorize("hasAuthority('audit:read')")
    public List<Map<String,Object>> audit(){return db.queryForList("SELECT occurred_at,actor,action,outcome,target,correlation_id FROM security_audit ORDER BY occurred_at DESC LIMIT 100");}
}
