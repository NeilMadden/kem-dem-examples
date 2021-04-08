package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * API for basic unauthenticated Key Encapsulation Mechanisms (KEMs).
 */
public interface KEM {

    /**
     * Generates a public and private key pair that can be used for key encapsulation.
     */
    KeyPair keyGen();

    /**
     * Derives a fresh symmetric key for encrypting a message and returns it along with an encapsulation of the key
     * that can only be recovered by the private key associated with the given public key. The encapsulation will
     * have IND-CCA2 security. Note: the secret key will always be a 256-bit AES key unless otherwise specified.
     *
     * @param recipientPublicKey the recipient's public key (cannot be null).
     * @return the secret key and its encapsulated form.
     */
    Pair<SecretKey, byte[]> encap(PublicKey recipientPublicKey);

    /**
     * Decapsulates a previously encapsulated secret key and returns it. If the key cannot be decapsulated because it
     * has been tampered with or incorrectly formed then {@link Optional#empty()} is returned.
     *
     * @param recipientPrivateKey the private key of the recipient of the encapsulated key.
     * @param encapsulatedKey the encapsulated key.
     * @return the decapsulated secret key, or empty() if it cannot be decapsulated.
     */
    Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey);
}
