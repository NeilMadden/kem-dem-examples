/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import kemdem.KEM;
import kemdem.MultiKem;
import kemdem.Pair;

public class KeyWrappingMultiKem implements MultiKem {
    private final KEM kem;
    private final KeyGenerator keyGenerator;

    public KeyWrappingMultiKem(KEM kem) {
        this.kem = kem;
        try {
            this.keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(256);
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public KeyPair keyGen() {
        return kem.keyGen();
    }

    @Override
    public Pair<SecretKey, byte[]> encap(PublicKey... recipients) {
        var demKey = keyGenerator.generateKey();

        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {
            out.writeShort(recipients.length);

            for (PublicKey recipient : recipients) {
                Pair<SecretKey, byte[]> kek = kem.encap(recipient);
                byte[] wrappedKey = wrap(kek.a, demKey);
                out.writeShort(kek.b.length);
                out.write(kek.b);
                out.writeShort(wrappedKey.length);
                out.write(wrappedKey);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return new Pair<>(demKey, baos.toByteArray());
    }

    @Override
    public Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey) {
        try (var in = new DataInputStream(new ByteArrayInputStream(encapsulatedKey))) {

            int numRecipients = in.readUnsignedShort();
            if (numRecipients > 100) { return Optional.empty(); }

            for (int i = 0; i < numRecipients; ++i) {
                int kekLength = in.readUnsignedShort();
                byte[] encapsulatedKek = in.readNBytes(kekLength);
                int wrappedDekLength = in.readUnsignedShort();
                byte[] wrappedDek = in.readNBytes(wrappedDekLength);

                Optional<SecretKey> dek = kem.decap(recipientPrivateKey, encapsulatedKek)
                        .flatMap(kek -> unwrap(kek, wrappedDek));
                if (dek.isPresent()) {
                    return dek;
                }
            }

        } catch (Exception e) {
            throw new RuntimeException(e);
        }

        return Optional.empty();
    }

    static byte[] wrap(SecretKey kek, SecretKey keyToWrap) {
        try {
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.WRAP_MODE, kek);
            return cipher.wrap(keyToWrap);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static Optional<SecretKey> unwrap(SecretKey kek, byte[] wrappedKey) {
        try {
            var cipher = Cipher.getInstance("AESWrap");
            cipher.init(Cipher.UNWRAP_MODE, kek);
            return Optional.of((SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY));
        } catch (GeneralSecurityException e) {
            return Optional.empty();
        }
    }
}
