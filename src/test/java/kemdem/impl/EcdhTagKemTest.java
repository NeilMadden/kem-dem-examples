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

import java.security.KeyPair;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class EcdhTagKemTest {

    private EcdhTagKem kem;

    @BeforeMethod
    public void setup() {
        kem = new EcdhTagKem();
    }

    @Test
    public void testBasicFuntionality() {
        // Given
        KeyPair keyPair = kem.keyGen();
        var tag = "foo".getBytes(UTF_8);

        // When
        var keyPlusState = kem.key(keyPair.getPublic());
        byte[] encap = kem.encap(keyPlusState.b, tag);
        var key = kem.decap(keyPair.getPrivate(), encap, tag).orElseThrow();

        // Then
        assertThat(key).isEqualTo(keyPlusState.a);
    }

    @Test
    public void shouldRejectIncorrectTag() {
        // Given
        KeyPair keyPair = kem.keyGen();
        var tag = "foo".getBytes(UTF_8);

        // When
        var keyPlusState = kem.key(keyPair.getPublic());
        byte[] encap = kem.encap(keyPlusState.b, tag);
        var key = kem.decap(keyPair.getPrivate(), encap, "bar".getBytes(UTF_8));

        // Then
        assertThat(key).isEmpty();
    }

}