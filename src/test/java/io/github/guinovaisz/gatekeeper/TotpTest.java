package io.github.guinovaisz.gatekeeper;

import org.junit.jupiter.api.Test;
import org.apache.commons.codec.binary.Base32;
import java.nio.charset.StandardCharsets;
import static org.assertj.core.api.Assertions.*;
import io.github.guinovaisz.gatekeeper.mfa.Totp;

class TotpTest {
    @Test void rfc6238Sha1VectorsAndReplayWindow() {
        String secret=new Base32().encodeAsString("12345678901234567890".getBytes(StandardCharsets.US_ASCII));
        long[] times={59,1111111109,1111111111,1234567890,2000000000,20000000000L};
        String[] sixDigits={"287082","081804","050471","005924","279037","353130"};
        for(int i=0;i<times.length;i++) assertThat(Totp.code(secret,times[i]/30)).isEqualTo(sixDigits[i]);
        assertThat(Totp.match(secret,"287082",1,-1)).isEqualTo(1);
        assertThat(Totp.match(secret,"287082",1,1)).isEqualTo(-1);
        assertThat(Totp.match(secret,"287082",4,-1)).isEqualTo(-1);
        assertThat(Totp.match(secret,"bad",1,-1)).isEqualTo(-1);
    }
}
