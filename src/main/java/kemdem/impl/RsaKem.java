package kemdem.impl;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kemdem.KEM;
import kemdem.Pair;

/**
 * Implements the RSA-KEM key encapsulation mechanism. This uses 3072-bit keys for ~128-bit security level.
 */
public class RsaKem implements KEM {
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public KeyPair keyGen() {
        try {
            var kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(new RSAKeyGenParameterSpec(3072, RSAKeyGenParameterSpec.F0));
            return kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new UnsupportedOperationException("RSA-KEM not supported", e);
        }
    }

    @Override
    public Pair<SecretKey, byte[]> encap(PublicKey recipientPublicKey) {
        var modulus = ((RSAPublicKey) recipientPublicKey).getModulus();

        // Pick a uniform random r between 2 and modulus-1 (inclusive).
        var r = BigInteger.ZERO;
        while (r.compareTo(BigInteger.TWO) < 0 || r.compareTo(modulus) >= 0) {
            r = new BigInteger(((RSAPublicKey) recipientPublicKey).getModulus().bitLength(), secureRandom);
        }

        // NB: r.toByteArray() returns the big-endian format, which is also that expected by eg RFC 5990 (appendix A)
        var rBytes = Utils.trimSignByte(r.toByteArray());

        byte[] encapsulatedKey;
        try {
            // RSA/ECB/NoPadding is Java's name for textbook RSA
            var cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
            // Java interprets rBytes here as a big-endian unsigned integer, so will exactly recover r
            encapsulatedKey = cipher.doFinal(rBytes);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Unable to encrypt", e);
        }

        var keyBytes = Utils.sha256(rBytes);
        var key = new SecretKeySpec(keyBytes, "AES");
        Arrays.fill(keyBytes, (byte) 0); // SecretKeySpec takes a defensive copy
        Arrays.fill(rBytes, (byte) 0);

        return new Pair<>(key, encapsulatedKey);
    }

    @Override
    public Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey) {

        try {
            var cipher = Cipher.getInstance("RSA/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, recipientPrivateKey);
            var rBytes = cipher.doFinal(encapsulatedKey);

            var keyBytes = Utils.sha256(rBytes);
            var key = new SecretKeySpec(keyBytes, "AES");
            Arrays.fill(keyBytes, (byte) 0); // SecretKeySpec takes a defensive copy
            Arrays.fill(rBytes, (byte) 0);

            return Optional.of(key);

        } catch (GeneralSecurityException e) {
            Logger.getLogger("RsaKem").log(Level.WARNING, "Unable to decapsulate key", e);
            return Optional.empty();
        }
    }
}
