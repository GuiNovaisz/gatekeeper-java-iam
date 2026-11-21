ALTER TABLE identity_account ADD CONSTRAINT mfa_pending_pair
 CHECK ((mfa_pending IS NULL) = (mfa_pending_until IS NULL));
ALTER TABLE oauth2_authorization ADD CONSTRAINT authorization_client_fk
 FOREIGN KEY(registered_client_id) REFERENCES oauth2_registered_client(id);
ALTER TABLE oauth2_authorization ADD CONSTRAINT code_time_order
 CHECK (authorization_code_expires_at IS NULL OR authorization_code_issued_at < authorization_code_expires_at);
ALTER TABLE oauth2_authorization ADD CONSTRAINT refresh_time_order
 CHECK (refresh_token_expires_at IS NULL OR refresh_token_issued_at < refresh_token_expires_at);
ALTER TABLE security_audit ADD CONSTRAINT audit_outcome CHECK(outcome IN ('SUCCESS','DENIED'));
