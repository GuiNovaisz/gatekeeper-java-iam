package io.github.guinovaisz.gatekeeper.mfa;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.apache.commons.codec.binary.Base32;

/** RFC 6238 HMAC-SHA1 profile: 6 digits, 30 seconds, +/- one step. */
public final class Totp {
    private Totp() {}
    public static String code(String base32, long step) {
        try {
            Mac mac=Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(new Base32().decode(base32),"HmacSHA1"));
            byte[] result=mac.doFinal(ByteBuffer.allocate(8).putLong(step).array());
            int offset=result[result.length-1]&15;
            int binary=ByteBuffer.wrap(result,offset,4).getInt()&0x7fffffff;
            return String.format(java.util.Locale.ROOT,"%06d",binary%1_000_000);
        } catch(Exception e) { throw new IllegalStateException("TOTP failed"); }
    }
    public static long match(String secret, String value, long currentStep, long lastStep) {
        if(value==null || !value.matches("[0-9]{6}")) return -1;
        long matched=-1;
        for(long step=currentStep-1;step<=currentStep+1;step++) {
            boolean equal=MessageDigest.isEqual(code(secret,step).getBytes(StandardCharsets.US_ASCII),value.getBytes(StandardCharsets.US_ASCII));
            if(equal && step>lastStep) matched=step;
        }
        return matched;
    }
}
