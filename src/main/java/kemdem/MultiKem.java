package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * A MultiKEM (or mKEM) is a {@link KEM} that supports sending a message to multiple recipients.
 */
public interface MultiKem {
    KeyPair keyGen();
    Pair<SecretKey, byte[]> encap(PublicKey...recipients);
    Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey);
}
