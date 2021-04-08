package kemdem.impl;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import kemdem.CommittingDEM;
import kemdem.Pair;

public class HmacSivDEM implements CommittingDEM {
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public SecretKey keyGen() {
        return new SecretKeySpec(secureRandom.generateSeed(32), "HmacSIV");
    }

    @Override
    public Pair<byte[], byte[]> enc(SecretKey key, byte[] message, byte[] label) {
        var macKey = new SecretKeySpec(Utils.sha256(key.getEncoded(), "mac".getBytes(UTF_8)), "HmacSHA256");
        var encKey = new SecretKeySpec(Utils.sha256(key.getEncoded(), "enc".getBytes(UTF_8)), "AES");
        var iv = secureRandom.generateSeed(16);

        var tag = mac(macKey, label, iv, message);
        var ciphertext = cipher(encKey, tag, message);

        return new Pair<>(Utils.concat(iv, ciphertext), tag);
    }

    @Override
    public byte[] dec(SecretKey key, byte[] ciphertext, byte[] label, byte[] tag) {
        var macKey = new SecretKeySpec(Utils.sha256(key.getEncoded(), "mac".getBytes(UTF_8)), "HmacSHA256");
        var encKey = new SecretKeySpec(Utils.sha256(key.getEncoded(), "enc".getBytes(UTF_8)), "AES");

        var iv = Arrays.copyOfRange(ciphertext, 0, 16);
        ciphertext = Arrays.copyOfRange(ciphertext, 16, ciphertext.length);

        var message = cipher(encKey, tag, ciphertext);
        var computedTag = mac(macKey, label, iv, message);

        if (!MessageDigest.isEqual(computedTag, tag)) {
            Arrays.fill(computedTag, (byte) 0);
            Arrays.fill(message, (byte) 0);
            throw new IllegalArgumentException("Authentication failed");
        }

        return message;
    }

    private static byte[] mac(SecretKey key, byte[]... data) {
        // There are several ways to convert a MAC that takes a single argument into one that takes a vector of
        // arguments. The original SIV formulation for AES-CMAC combines separate MAC invocations using GF(2^128)
        // arithmetic. We could easily do the same in GF(2^256) for HMAC-SHA256. Or we could just use an unambiguous
        // encoding to combine the separate chunks into one. In this case, we use a cascade where the tag from the
        // previous iteration is used as the key for the next iteration. This works because HMAC-SHA256 is a PRF. It
        // is vulnerable to a trivial length-extension attack, but in this case we are always processing a fixed
        // number of chunks: (label, iv, plaintext). (It is efficient because there is no expensive key schedule for
        // HMAC-SHA256 - it would be prohibitively expensive to do this for AES).
        try {
            var mac = Mac.getInstance(key.getAlgorithm());
            mac.init(key);
            byte[] tag = null;
            for (byte[] chunk : data) {
                tag = mac.doFinal(chunk);
                mac.init(new SecretKeySpec(tag, key.getAlgorithm()));
            }
            return tag;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] cipher(SecretKey key, byte[] iv, byte[] data) {
        try {
            var cipher = Cipher.getInstance("AES/CTR/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv, 0, 16));
            return cipher.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }
}
