/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.AKEM;
import kemdem.Pair;

public class EcdhAkemTest {
    private AKEM ecdhAkem;

    @BeforeMethod
    public void setup() {
        ecdhAkem = new EcdhAkem();
    }

    @Test
    public void testBasicFunctionality() {
        // Given
        KeyPair senderKeys = ecdhAkem.keyGen();
        KeyPair recipientKeys = ecdhAkem.keyGen();

        // When
        Pair<SecretKey, byte[]> encapKey = ecdhAkem.authEncap(senderKeys.getPrivate(), recipientKeys.getPublic());
        SecretKey decapKey = ecdhAkem.authDecap(senderKeys.getPublic(), recipientKeys.getPrivate(), encapKey.b)
                .orElseThrow();

        // Then
        assertThat(decapKey).isEqualTo(encapKey.a);
    }
}