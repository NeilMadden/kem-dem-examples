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
