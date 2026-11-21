package io.github.guinovaisz.gatekeeper;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;
import io.github.guinovaisz.gatekeeper.credential.PasswordPolicy;
import io.github.guinovaisz.gatekeeper.identity.IdentityRepository;

class PasswordPolicyTest {
    @Test void passphrasesAndUnicodeAreSupportedWithoutCompositionRules() {
        assertThatCode(()->PasswordPolicy.validate("uma frase longa de teste 🔒")).doesNotThrowAnyException();
        assertThatThrownBy(()->PasswordPolicy.validate("short")).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->PasswordPolicy.validate("x".repeat(129))).isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(()->PasswordPolicy.validate("passwordpassword")).isInstanceOf(IllegalArgumentException.class);
    }
    @Test void normalizationIsLocaleIndependent() {
        assertThat(IdentityRepository.normalize(" User@Example.com ")).isEqualTo("user@example.com");
    }
}
