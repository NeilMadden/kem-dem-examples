/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * An authenticated {@link KEM}. An AKEM allows a recipient to be assured that the encapsulated key was produced by
 * the holder of a particular key.
 */
public interface AKEM {
    KeyPair keyGen();
    Pair<SecretKey, byte[]> authEncap(PrivateKey senderPrivateKey, PublicKey recipientPublicKey);
    Optional<SecretKey> authDecap(PublicKey senderPublicKey, PrivateKey recipientPrivateKey, byte[] encapsulatedKey);
}
