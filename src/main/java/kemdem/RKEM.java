package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

/**
 * A "replyable" AKEM (rKEM) is an authenticated KEM that allows for an ongoing conversation between two parties.
 * This captures the notion of an interactive protocol like Noise or Signal, where the keys change regularly. An
 * rKEM allows for full forward secrecy after each party has exchanged one message.
 *
 * @param <State> the type of state.
 */
public interface RKEM<State> {

    /**
     * Generates a key pair for use by this party.
     *
     * @return the long-term private and public key used to authenticate and encapsulated keys for this party.
     */
    KeyPair keyGen();

    /**
     * Begins a conversation session between two or more parties. This method should be called either by an
     * originator when starting a new conversation, or by a recipient when they receive a message outside of a
     * previously established conversation.
     *
     * @param secretKey the secret key of the local party.
     * @param publicKeys the public key(s) of the remote parties.
     * @return a fresh state object encapsulating this new conversation.
     */
    State begin(PrivateKey secretKey, PublicKey...publicKeys);

    /**
     * Returns the {@link DEM} key to use for encrypting messages based on the current state of the conversation.
     *
     * @param state the conversation state.
     * @return the current DEM key.
     */
    SecretKey key(State state);

    /**
     * Encapsulates the {@linkplain #key(Object) current DEM key} to all recipients and returns it along with a new
     * state. The new state should be used to process any reply messages received from the recipients.
     *
     * @param state the current conversation state.
     * @param tag a tag to include in the authentication of the KEM. This is typically either the entire ciphertext
     *            output from a {@link DEM} or the compactly committing authentication tag from a
     *            {@link CommittingDEM}.
     * @return the encapsulated key and a new state.
     */
    Pair<State, byte[]> authEncap(State state, byte[] tag);

    /**
     * Authenticates and decapsulates the DEM key received from another party. If authentication of the encapsulated
     * key or the associated tag fails then an empty result is returned, otherwise the DEM decryption key and a new
     * state is returned. The new state should be used with the {@link #key(Object)} method to encrypt any response
     * to this message.
     *
     * @param state the current conversation state.
     * @param ek the encapsulated key.
     * @param tag the tag to include in the KEM authentication.
     * @return a new state and the DEM key or an empty result if authentication fails.
     */
    Optional<Pair<State, SecretKey>> authDecap(State state, byte[] ek, byte[] tag);
}
