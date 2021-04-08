package kemdem.impl;

import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Optional;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kemdem.KEM;
import kemdem.Pair;
import kemdem.TagKEM;
import kemdem.impl.EcdhTagKem.KemState;

public class EcdhTagKem implements TagKEM<KemState> {
    private final KEM kem = new EcdhKem();

    @Override
    public KeyPair keyGen() {
        return kem.keyGen();
    }

    @Override
    public Pair<SecretKey, KemState> key(PublicKey recipient) {
        var encapKey = kem.encap(recipient);

        var macKey = new SecretKeySpec(Utils.sha256(encapKey.a.getEncoded(), new byte[] { 0 }), "HmacSHA256");
        var encKey = new SecretKeySpec(Utils.sha256(encapKey.a.getEncoded(), new byte[] { 1 }), "AES");

        return new Pair<>(encKey, new KemState(macKey, encapKey.b));
    }

    @Override
    public byte[] encap(KemState state, byte[] tag) {
        try {
            var mac = Mac.getInstance("HmacSHA256");
            mac.init(state.macKey);
            mac.update(state.encapsulatedKey);
            mac.update(tag);
            var sig = mac.doFinal();

            var buffer = ByteBuffer.allocate(state.encapsulatedKey.length + sig.length)
                    .put(state.encapsulatedKey).put(sig);

            return buffer.array();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey, byte[] tag) {

        var macTag = Arrays.copyOfRange(encapsulatedKey, encapsulatedKey.length - 32, encapsulatedKey.length);
        var encapKey = Arrays.copyOf(encapsulatedKey, encapsulatedKey.length - 32);

        return kem.decap(recipientPrivateKey, encapKey).flatMap(masterKey -> {
            var macKey = new SecretKeySpec(Utils.sha256(masterKey.getEncoded(), new byte[]{0}), "HmacSHA256");
            var encKey = new SecretKeySpec(Utils.sha256(masterKey.getEncoded(), new byte[]{1}), "AES");

            try {
                var mac = Mac.getInstance("HmacSHA256");
                mac.init(macKey);
                mac.update(encapKey);
                mac.update(tag);
                var sig = mac.doFinal();

                if (!MessageDigest.isEqual(sig, macTag)) {
                    return Optional.empty();
                }

                return Optional.of(encKey);

            } catch (GeneralSecurityException e) {
                return Optional.empty();

            }
        });
    }

    public static class KemState {
        private final SecretKey macKey;
        private final byte[] encapsulatedKey;

        KemState(SecretKey macKey, byte[] encapsulatedKey) {
            this.macKey = macKey;
            this.encapsulatedKey = encapsulatedKey;
        }
    }
}
