package kemdem;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Optional;

import javax.crypto.SecretKey;

public interface TagAKEM<State> {
    KeyPair keyGen();
    Pair<SecretKey, State> key(PrivateKey senderKey, PublicKey recipientKey);
    byte[] authEncap(State state, byte[] tag);
    Optional<SecretKey> authDecap(PublicKey senderKey, PrivateKey recipientKey, byte[] encapsulatedKey, byte[] tag);
}
