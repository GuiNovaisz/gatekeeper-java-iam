package io.github.guinovaisz.gatekeeper.credential;

import java.util.UUID;

/** Boundary for an out-of-band delivery provider. Never expose delivery through HTTP. */
public interface RecoveryDelivery { void deliver(UUID identity,String token); }
