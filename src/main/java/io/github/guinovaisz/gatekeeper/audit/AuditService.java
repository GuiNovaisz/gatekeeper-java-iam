package io.github.guinovaisz.gatekeeper.audit;

import java.sql.Timestamp;
import java.time.Clock;
import java.util.UUID;
import io.micrometer.core.instrument.MeterRegistry;
import org.slf4j.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

@Service
public class AuditService {
    private static final Logger LOG = LoggerFactory.getLogger(AuditService.class);
    private final JdbcTemplate db;
    private final Clock clock;
    private final MeterRegistry metrics;
    public AuditService(JdbcTemplate db, Clock clock, MeterRegistry metrics) { this.db=db; this.clock=clock; this.metrics=metrics; }
    public void record(UUID actor, String action, String outcome, UUID target) {
        UUID correlation = UUID.randomUUID();
        db.update("INSERT INTO security_audit VALUES (?,?,?,?,?,?,?)", UUID.randomUUID(), Timestamp.from(clock.instant()),actor,action,outcome,target,correlation);
        metrics.counter("gatekeeper.security.events", "action",action,"outcome",outcome).increment();
        LOG.info("security_event category={} outcome={} actorId={} correlationId={}",action,outcome,actor,correlation);
    }
}
