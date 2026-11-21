package io.github.guinovaisz.gatekeeper.security;

import java.sql.Timestamp;
import java.time.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import io.github.guinovaisz.gatekeeper.shared.Secrets;

@Service
public class Throttle {
    private final JdbcTemplate db; private final Clock clock;
    public Throttle(JdbcTemplate db, Clock clock) { this.db=db; this.clock=clock; }
    public boolean allow(String kind, String identifier, int limit, Duration window) {
        // Consume attempts before authentication; independent transactions survive rejected requests.
        Instant now=clock.instant();
        Integer count=db.queryForObject("""
          INSERT INTO security_throttle(bucket,attempts,expires_at) VALUES (?,1,?)
          ON CONFLICT(bucket) DO UPDATE SET
            attempts=CASE WHEN security_throttle.expires_at<=? THEN 1 ELSE security_throttle.attempts+1 END,
            expires_at=CASE WHEN security_throttle.expires_at<=? THEN EXCLUDED.expires_at ELSE security_throttle.expires_at END
          RETURNING attempts
          """,Integer.class,kind+":"+Secrets.digest(identifier),Timestamp.from(now.plus(window)),Timestamp.from(now),Timestamp.from(now));
        return count!=null && count<=limit;
    }
}
