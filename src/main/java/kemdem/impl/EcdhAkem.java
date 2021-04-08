/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import static kemdem.impl.EcdhKem.ecdh;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kemdem.AKEM;
import kemdem.Pair;

/**
 * An implicitly authenticated KEM based on ECDH key agreement.
 */
public class EcdhAkem implements AKEM {

    @Override
    public KeyPair keyGen() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public Pair<SecretKey, byte[]> authEncap(PrivateKey senderPrivateKey, PublicKey recipientPublicKey) {
        var ephemeralKeys = keyGen();
        var ephemeralSharedSecret = ecdh(ephemeralKeys.getPrivate(), recipientPublicKey);
        var staticSharedSecret = ecdh(senderPrivateKey, recipientPublicKey);
        var ephemeralPublicKey = ephemeralKeys.getPublic().getEncoded();
        var key = new SecretKeySpec(Utils.sha256(ephemeralSharedSecret, staticSharedSecret, ephemeralPublicKey), "AES");
        Arrays.fill(ephemeralSharedSecret, (byte) 0);
        Arrays.fill(staticSharedSecret, (byte) 0);

        // Note: Java's getEncoded() will return the public key in X.509 format, where it is prefixed by an algorithm
        // identifier and DER-encoded. This adds a few bytes of unnecessary overhead but is otherwise harmless.
        return new Pair<>(key, ephemeralPublicKey);
    }

    @Override
    public Optional<SecretKey> authDecap(PublicKey senderPublicKey, PrivateKey recipientPrivateKey, byte[] encapsulatedKey) {
        try {
            var keyFactory = KeyFactory.getInstance("X25519");
            var ephemeralPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encapsulatedKey));

            var ephemeralSharedSecret = ecdh(recipientPrivateKey, ephemeralPublicKey);
            var staticSharedSecret = ecdh(recipientPrivateKey, senderPublicKey);
            var key = new SecretKeySpec(Utils.sha256(ephemeralSharedSecret, staticSharedSecret, encapsulatedKey), "AES");
            Arrays.fill(ephemeralSharedSecret, (byte) 0);
            Arrays.fill(staticSharedSecret, (byte) 0);

            return Optional.of(key);
        } catch (GeneralSecurityException e) {
            Logger.getLogger("EcdhKem").log(Level.WARNING, "Unable to recover ECDH-KEM encapsulated key", e);
            return Optional.empty();
        }
    }
}
