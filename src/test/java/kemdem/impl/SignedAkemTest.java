/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.AKEM;

public class SignedAkemTest {

    private AKEM signedAkem;

    @BeforeMethod
    public void setup() {
        signedAkem = new SignedAkem(new RsaKem());
    }

    @Test
    public void testBasicFunctionality() {
        // Given
        var senderKeys = signedAkem.keyGen();
        var recipientKeys = signedAkem.keyGen();

        // When
        var encapKey = signedAkem.authEncap(senderKeys.getPrivate(), recipientKeys.getPublic());
        var decapKey = signedAkem.authDecap(senderKeys.getPublic(), recipientKeys.getPrivate(), encapKey.b)
                .orElseThrow();

        // Then
        assertThat(decapKey).isEqualTo(encapKey.a);
    }

}