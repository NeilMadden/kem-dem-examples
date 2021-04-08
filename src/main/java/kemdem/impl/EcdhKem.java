package kemdem.impl;

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
import java.util.concurrent.ArrayBlockingQueue;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kemdem.KEM;
import kemdem.Pair;

/**
 * A KEM based on elliptic curve Diffie-Hellman ephemeral-static key agreement. This uses X25519 key agreement
 * because why wouldn't you?
 */
public class EcdhKem implements KEM {

    private final KeyPairGenerator keyPairGenerator;
    private final BlockingQueue<KeyPair> keyPairs = new ArrayBlockingQueue<>(100);

    public EcdhKem() {
        try {
            keyPairGenerator = KeyPairGenerator.getInstance("X25519");
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
        Executors.newSingleThreadExecutor().execute(() -> {
            while (true) {
                try {
                    keyPairs.put(keyPairGenerator.generateKeyPair());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
        });
    }

    @Override
    public KeyPair keyGen() {
        try {
            return keyPairs.take();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Interrupted while waiting");
        }
    }

    @Override
    public Pair<SecretKey, byte[]> encap(PublicKey recipientPublicKey) {
        var ephemeralKeys = keyGen();
        var sharedSecret = ecdh(ephemeralKeys.getPrivate(), recipientPublicKey);
        var ephemeralPublicKey = ephemeralKeys.getPublic().getEncoded();
        var key = new SecretKeySpec(Utils.sha256(sharedSecret, ephemeralPublicKey), "AES");
        Arrays.fill(sharedSecret, (byte) 0);

        // Note: Java's getEncoded() will return the public key in X.509 format, where it is prefixed by an algorithm
        // identifier and DER-encoded. This adds a few bytes of unnecessary overhead but is otherwise harmless.
        return new Pair<>(key, ephemeralPublicKey);
    }

    @Override
    public Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey) {
        try {
            var keyFactory = KeyFactory.getInstance("X25519");
            var ephemeralPublicKey = keyFactory.generatePublic(new X509EncodedKeySpec(encapsulatedKey));

            var sharedSecret = ecdh(recipientPrivateKey, ephemeralPublicKey);
            var key = new SecretKeySpec(Utils.sha256(sharedSecret, encapsulatedKey), "AES");
            Arrays.fill(sharedSecret, (byte) 0);

            return Optional.of(key);
        } catch (GeneralSecurityException e) {
            Logger.getLogger("EcdhKem").log(Level.WARNING, "Unable to recover ECDH-KEM encapsulated key", e);
            return Optional.empty();
        }
    }

    static byte[] ecdh(PrivateKey privateKey, PublicKey publicKey) {
        try {
            var ecdh = KeyAgreement.getInstance("X25519");
            ecdh.init(privateKey);
            ecdh.doPhase(publicKey, true);
            return ecdh.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
