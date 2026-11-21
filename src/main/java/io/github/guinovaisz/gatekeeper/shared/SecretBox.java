package io.github.guinovaisz.gatekeeper.shared;

import javax.crypto.Cipher;
import javax.crypto.spec.*;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public final class SecretBox {
    private final SecretKeySpec key;
    public SecretBox(@Value("${gatekeeper.mfa-key}") String encoded) {
        byte[] bytes = Base64.getDecoder().decode(encoded);
        if (bytes.length != 32) throw new IllegalArgumentException("MFA key must contain 32 bytes");
        key = new SecretKeySpec(bytes, "AES");
    }
    public String seal(String clear) {
        try {
            byte[] iv = Secrets.bytes(12);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
            cipher.updateAAD("gatekeeper:mfa:v1".getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(iv) + "." + Base64.getEncoder().encodeToString(cipher.doFinal(clear.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception e) { throw new IllegalStateException("Secret protection failed"); }
    }
    public String open(String sealed) {
        try {
            String[] parts = sealed.split("\\.", 2);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, Base64.getDecoder().decode(parts[0])));
            cipher.updateAAD("gatekeeper:mfa:v1".getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(Base64.getDecoder().decode(parts[1])), StandardCharsets.UTF_8);
        } catch (Exception e) { throw new IllegalStateException("Secret protection failed"); }
    }
}
