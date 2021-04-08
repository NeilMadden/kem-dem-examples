package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

public interface TagKEM<State> {
    KeyPair keyGen();
    Pair<SecretKey, State> key(PublicKey recipient);
    byte[] encap(State state, byte[] tag);
    Optional<SecretKey> decap(PrivateKey recipientPrivateKey, byte[] encapsulatedKey, byte[] tag);
}
