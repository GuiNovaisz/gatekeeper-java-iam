package io.github.guinovaisz.gatekeeper.identity;

import java.sql.*;
import java.util.*;
import org.springframework.jdbc.core.*;
import org.springframework.stereotype.Repository;

@Repository
public class IdentityRepository {
    private final JdbcTemplate db;
    private final RowMapper<Identity> mapper=(r,n)->new Identity(r.getObject("id",UUID.class),r.getString("login"),r.getString("password_hash"),r.getString("state"),r.getLong("credential_version"),r.getString("mfa_secret"),r.getString("mfa_pending"),r.getTimestamp("mfa_pending_until")==null?null:r.getTimestamp("mfa_pending_until").toInstant(),r.getLong("mfa_last_step"));
    public IdentityRepository(JdbcTemplate db) { this.db=db; }
    public static String normalize(String login) { return login.trim().toLowerCase(Locale.ROOT); }
    public Optional<Identity> byLogin(String login) { return db.query("SELECT * FROM identity_account WHERE login=?",mapper,normalize(login)).stream().findFirst(); }
    public Optional<Identity> find(UUID id) { return db.query("SELECT * FROM identity_account WHERE id=?",mapper,id).stream().findFirst(); }
    public Identity lock(UUID id) { return db.queryForObject("SELECT * FROM identity_account WHERE id=? FOR UPDATE",mapper,id); }
    public List<String> permissions(UUID id) { return db.queryForList("SELECT DISTINCT rp.permission_name FROM identity_role ir JOIN role_permission rp ON rp.role_name=ir.role_name WHERE ir.identity_id=?",String.class,id); }
}
