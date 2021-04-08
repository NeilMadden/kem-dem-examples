package kemdem;

import javax.crypto.SecretKey;

/**
 * A DEM that is compactly committing. The {@link #enc(SecretKey, byte[], byte[])} method returns a MAC tag along
 * with the ciphertext that commits to both the key and the message (and label, if supplied).
 */
public interface CommittingDEM {
    SecretKey keyGen();
    Pair<byte[], byte[]> enc(SecretKey key, byte[] message, byte[] label);
    byte[] dec(SecretKey key, byte[] ciphertext, byte[] label, byte[] tag);
}
