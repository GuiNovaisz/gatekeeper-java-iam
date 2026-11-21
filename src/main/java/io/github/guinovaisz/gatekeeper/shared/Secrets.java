package io.github.guinovaisz.gatekeeper.shared;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

public final class Secrets {
    private static final SecureRandom RANDOM = new SecureRandom();
    private Secrets() {}
    public static byte[] bytes(int length) { byte[] bytes = new byte[length]; RANDOM.nextBytes(bytes); return bytes; }
    public static String token(int bytes) { return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes(bytes)); }
    public static String digest(String value) {
        try { return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8))); }
        catch (NoSuchAlgorithmException e) { throw new IllegalStateException(e); }
    }
}
