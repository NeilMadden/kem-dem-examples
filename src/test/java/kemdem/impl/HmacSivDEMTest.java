/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.CommittingDEM;

public class HmacSivDEMTest {

    private CommittingDEM dem;

    @BeforeMethod
    public void setup() {
        dem = new HmacSivDEM();
    }

    @Test
    public void testBasicFunctionality() {
        // Given
        var key = dem.keyGen();
        var message = "Hello, World!";
        var label = "label".getBytes(UTF_8);

        // When
        var cipherTextAndTag = dem.enc(key, message.getBytes(UTF_8), label);
        var decrypted = dem.dec(key, cipherTextAndTag.a, label, cipherTextAndTag.b);

        // Then
        assertThat(decrypted).asString(UTF_8).isEqualTo(message);
    }

    @Test
    public void testBindingToTagKem() {
        // Given
        var kem = new EcdhTagKem();
        var keyPair = kem.keyGen();
        var key = kem.key(keyPair.getPublic());
        var message = "Hello, World!";
        var label = "label".getBytes(UTF_8);

        // When
        var correctMessage = dem.enc(key.a, message.getBytes(UTF_8), label);
        var differentMessage = dem.enc(key.a, "Goodbye, World!".getBytes(UTF_8), label);
        var encapKey = kem.encap(key.b, correctMessage.b);

        // Then
        var decapKey = kem.decap(keyPair.getPrivate(), encapKey, correctMessage.b).orElseThrow();
        var decrypted = dem.dec(decapKey, correctMessage.a, label, correctMessage.b);
        assertThat(decrypted).asString(UTF_8).isEqualTo(message);

        // Try to decap with different tag
        Optional<SecretKey> end = kem.decap(keyPair.getPrivate(), encapKey, differentMessage.b);
        assertThat(end).isEmpty();
    }

}