package kemdem.impl;

import static kemdem.impl.EcdhKem.ecdh;
import static kemdem.impl.KeyWrappingMultiKem.unwrap;
import static kemdem.impl.KeyWrappingMultiKem.wrap;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import kemdem.RKEM;
import kemdem.Pair;
import kemdem.impl.X25519RKEM.X25519State;

public class X25519RKEM implements RKEM<X25519State> {

    private final KeyGenerator dataKeyGenerator;

    public X25519RKEM(KeyGenerator dataKeyGenerator) {
        this.dataKeyGenerator = dataKeyGenerator;
    }

    public X25519RKEM() {
        this(defaultKeyGenerator());
    }

    private static KeyGenerator defaultKeyGenerator() {
        try {
            var kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            return kg;
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }

    }

    @Override
    public KeyPair keyGen() {
        try {
            return KeyPairGenerator.getInstance("X25519").generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new UnsupportedOperationException(e);
        }
    }

    @Override
    public X25519State begin(PrivateKey secretKey, PublicKey... publicKeys) {
        if (publicKeys.length > 65535) {
            throw new IllegalArgumentException("Too many recipients");
        }
        var ephemeralKeys = keyGen();
        var dataKey = dataKeyGenerator.generateKey();
        var state = new X25519State(secretKey, List.of(publicKeys), ephemeralKeys, dataKey);
        System.out.println("New state: " + state);
        return state;
    }

    @Override
    public SecretKey key(X25519State state) {
        System.out.println("DEM key: " + base64url(state.dataKey.getEncoded()));
        return state.dataKey;
    }

    @Override
    public Pair<X25519State, byte[]> authEncap(X25519State state, byte[] tag) {
        System.out.println("Encapsulating key for state: " + state);
        var baos = new ByteArrayOutputStream();
        try (var out = new DataOutputStream(baos)) {
            var encodedEpk = state.ephemeralKeys.getPublic().getEncoded();
            out.writeShort(encodedEpk.length);
            out.write(encodedEpk);
            out.writeShort(state.publicKeys.size());

            for (PublicKey recipient : state.publicKeys) {
                var ephemeralSharedSecret = ecdh(state.ephemeralKeys.getPrivate(), recipient);
                var staticSharedSecret = ecdh(state.privateKey, recipient);
                // NB: the shared secrets and encodedEpk will always be the same size so this encoding is unambiguous
                var keyWrapKey = new SecretKeySpec(
                        Utils.sha256(ephemeralSharedSecret, staticSharedSecret, encodedEpk, tag), "AES");
                var wrappedKey = wrap(keyWrapKey, state.dataKey);
                assert wrappedKey.length < 65536;

                out.writeShort(wrappedKey.length);
                out.write(wrappedKey);
            }

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Replies should be encrypted to the ephemeral public key used in the original message. From this point on
        // we have "ratcheted" our original private key and it no longer needs to be used for subsequent messages.
        var newState = begin(state.ephemeralKeys.getPrivate(), state.publicKeys.toArray(new PublicKey[0]));
        return new Pair<>(newState, baos.toByteArray());
    }

    @Override
    public Optional<Pair<X25519State, SecretKey>> authDecap(X25519State state, byte[] ek, byte[] tag) {
        System.out.println("Decapsulating key in state: " + state);
        try (var in = new DataInputStream(new ByteArrayInputStream(ek))) {
            var epkLength = in.readUnsignedShort();
            var encodedEpk = in.readNBytes(epkLength);
            System.out.println("Decoded EPK: " + base64url(encodedEpk));
            var epk = decodePublicKey(encodedEpk);
            var numRecipients = in.readUnsignedShort();
            for (int i = 0; i < numRecipients; ++i) {
                var ephemeralSharedSecret = ecdh(state.privateKey, epk);
                var staticSharedSecret = ecdh(state.privateKey, state.publicKeys.get(0));
                var keyWrapKey = new SecretKeySpec(
                        Utils.sha256(ephemeralSharedSecret, staticSharedSecret, encodedEpk, tag), "AES");

                var wrappedKeyLen = in.readUnsignedShort();
                var wrappedKey = in.readNBytes(wrappedKeyLen);
                var optKey = unwrap(keyWrapKey, wrappedKey).map(key -> {
                    var newState = begin(state.privateKey, epk);
                    return new Pair<>(newState, key);
                });
                if (optKey.isPresent()) {
                    return optKey;
                }
            }
        } catch (IOException e) {
            Logger.getLogger(getClass().getName()).log(Level.WARNING, "Unable to decapsulate key", e);
        }
        return Optional.empty();
    }

    private static PublicKey decodePublicKey(byte[] encoded) throws IOException {
        try {
            return KeyFactory.getInstance("X25519").generatePublic(new X509EncodedKeySpec(encoded));
        } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
            throw new IOException("Invalid encoded public key", e);
        }
    }

    public static final class X25519State {
        private final PrivateKey privateKey;
        private final List<PublicKey> publicKeys;
        private final KeyPair ephemeralKeys;
        private final SecretKey dataKey;

        X25519State(PrivateKey privateKey, List<PublicKey> publicKeys, KeyPair ephemeralKeys, SecretKey dataKey) {
            this.privateKey = privateKey;
            this.publicKeys = publicKeys;
            this.ephemeralKeys = ephemeralKeys;
            this.dataKey = dataKey;
        }

        @Override
        public String toString() {
            return "X25519State{" +
                    "privateKey=" + base64url(Utils.sha256(privateKey.getEncoded())) +
                    ", publicKeys=" + base64url(publicKeys.get(0).getEncoded()) +
                    ", esk=" + base64url(Utils.sha256(ephemeralKeys.getPrivate().getEncoded())) +
                    ", epk=" + base64url(ephemeralKeys.getPublic().getEncoded()) +
                    ", dataKey=" + dataKey +
                    '}';
        }
    }

    private static String base64url(byte[] data) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(data);
    }
}
