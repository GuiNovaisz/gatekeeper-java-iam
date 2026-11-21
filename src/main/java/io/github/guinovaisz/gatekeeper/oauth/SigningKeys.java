package io.github.guinovaisz.gatekeeper.oauth;

import java.nio.file.*;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.Certificate;
import java.util.*;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.jwk.source.*;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;

@Configuration
public class SigningKeys {
    @Bean JWKSource<SecurityContext> jwkSource(@Value("${gatekeeper.key-store}") String path,@Value("${gatekeeper.key-store-password}") String password) throws Exception {
        KeyStore store=KeyStore.getInstance("PKCS12");
        char[] pass=password.toCharArray();
        try(var stream=Files.newInputStream(Path.of(path))) {store.load(stream,pass);}
        try {
            Certificate certificate=store.getCertificate("signing");
            RSAPrivateKey privateKey=(RSAPrivateKey)store.getKey("signing",pass);
            RSAPublicKey publicKey=(RSAPublicKey)certificate.getPublicKey();
            if(publicKey.getModulus().bitLength()<3072) throw new IllegalArgumentException("RSA key must be >=3072 bits");
            RSAKey key=new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(io.github.guinovaisz.gatekeeper.shared.Secrets.digest(Base64.getEncoder().encodeToString(publicKey.getEncoded())).substring(0,24)).build();
            return new ImmutableJWKSet<>(new JWKSet(key));
        } finally {Arrays.fill(pass,'\0');}
    }
}
