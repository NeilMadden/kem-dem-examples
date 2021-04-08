package kemdem.impl;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.SecretKey;

import kemdem.AKEM;
import kemdem.KEM;
import kemdem.Pair;

/**
 * Implements an {@link AKEM} by wrapping the output of an unauthenticated {@link KEM} in a signature. This version
 * uses RSA-PSS signatures to emphasise the large size of encapsulated keys with this approach. EC signatures would
 * be much smaller.
 */
public class SignedAkem implements AKEM {

    private final KEM kem;

    public SignedAkem(KEM kem) {
        this.kem = kem;
    }

    @Override
    public KeyPair keyGen() {
        // Even if the keys are compatible, we should really use independent keys for KEM vs signature, so we
        // generate two pairs here and then combine them to look like one.
        KeyPair sigKeys = new RsaKem().keyGen();
        KeyPair kemKeys = kem.keyGen();
        return new KeyPair(new SignedAkem.PublicKeyPair(sigKeys.getPublic(), kemKeys.getPublic()),
                new SignedAkem.PrivateKeyPair(sigKeys.getPrivate(), kemKeys.getPrivate()));
    }

    @Override
    public Pair<SecretKey, byte[]> authEncap(PrivateKey senderPrivateKey, PublicKey recipientPublicKey) {
        // Unpack sender/recipient key pairs
        if (recipientPublicKey instanceof PublicKeyPair) {
            recipientPublicKey = ((PublicKeyPair) recipientPublicKey).kemKey;
        }
        if (senderPrivateKey instanceof PrivateKeyPair) {
            senderPrivateKey = ((PrivateKeyPair) senderPrivateKey).sigKey;
        }

        Pair<SecretKey, byte[]> kemKey = kem.encap(recipientPublicKey);
        var signature = sign(senderPrivateKey, kemKey.b);
        // Concatenate the encapsulated key and the signature
        var buffer = ByteBuffer.allocate(kemKey.b.length + signature.length + 4).order(ByteOrder.LITTLE_ENDIAN);
        buffer.putInt(kemKey.b.length).put(kemKey.b).put(signature);
        return new Pair<>(kemKey.a, buffer.array());
    }

    @Override
    public Optional<SecretKey> authDecap(PublicKey senderPublicKey, PrivateKey recipientPrivateKey, byte[] encapsulatedKey) {
        // Unpack sender/recipient key pairs
        if (senderPublicKey instanceof PublicKeyPair) {
            senderPublicKey = ((PublicKeyPair) senderPublicKey).sigKey;
        }
        if (recipientPrivateKey instanceof PrivateKeyPair) {
            recipientPrivateKey = ((PrivateKeyPair) recipientPrivateKey).kemKey;
        }

        var buffer = ByteBuffer.wrap(encapsulatedKey).order(ByteOrder.LITTLE_ENDIAN);
        // Parse the encapsulated key into the key and the signature
        var encapsulatedKeyLen = buffer.getInt();
        if (encapsulatedKeyLen > buffer.remaining()) { return Optional.empty(); }
        byte[] kemEncap = new byte[encapsulatedKeyLen];
        buffer.get(kemEncap);
        byte[] signature = new byte[buffer.remaining()];
        buffer.get(signature);

        if (!verify(senderPublicKey, kemEncap, signature)) { return Optional.empty(); }
        return kem.decap(recipientPrivateKey, kemEncap);
    }

    private static byte[] sign(PrivateKey privateKey, byte[] data) {
        try {
            var signature = Signature.getInstance("RSASSA-PSS");
            signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    private static boolean verify(PublicKey publicKey, byte[] data, byte[] sig) {
        try {
            var signature = Signature.getInstance("RSASSA-PSS");
            signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
            signature.initVerify(publicKey);
            signature.update(data);
            return signature.verify(sig);
        } catch (GeneralSecurityException e) {
            Logger.getLogger("SignedAkem").log(Level.WARNING, "Signature verification threw exception", e);
            return false;
        }
    }

    private static class PrivateKeyPair implements PrivateKey {
        private final PrivateKey sigKey;
        private final PrivateKey kemKey;

        private PrivateKeyPair(PrivateKey sigKey, PrivateKey kemKey) {
            this.sigKey = sigKey;
            this.kemKey = kemKey;
        }

        @Override
        public String getAlgorithm() {
            return "SignedAkemPair";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    private static class PublicKeyPair implements PublicKey {
        private final PublicKey sigKey;
        private final PublicKey kemKey;

        private PublicKeyPair(PublicKey sigKey, PublicKey kemKey) {
            this.sigKey = sigKey;
            this.kemKey = kemKey;
        }

        @Override
        public String getAlgorithm() {
            return "SignedAkemPair";
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }
}
