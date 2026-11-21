package io.github.guinovaisz.gatekeeper.credential;

import java.util.Set;

public final class PasswordPolicy {
    private PasswordPolicy() {}
    private static final Set<String> COMMON=Set.of("passwordpassword", "123456789012345", "correct horse battery staple", "abcdefghijklmnop");
    public static void validate(String password) {
        if(password==null || password.codePointCount(0,password.length())<15 || password.codePointCount(0,password.length())>128 || COMMON.contains(password.toLowerCase(java.util.Locale.ROOT)))
            throw new IllegalArgumentException("Password must contain 15–128 characters and avoid the common-password list");
    }
}
