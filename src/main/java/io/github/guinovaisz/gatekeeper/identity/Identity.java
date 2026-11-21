package io.github.guinovaisz.gatekeeper.identity;

import java.util.UUID;

public record Identity(UUID id, String login, String passwordHash, String state, long credentialVersion,
                       String mfaSecret, String mfaPending, java.time.Instant pendingUntil, long lastStep) {
    @Override public String toString() { return "Identity[id="+id+",state="+state+"]"; }
}
