package kemdem;

import javax.crypto.SecretKey;

/**
 * This interface represents the original one-time secure DEM.
 */
public interface DEM {
    SecretKey keyGen();
    byte[] enc(SecretKey key, byte[] message);
    byte[] dec(SecretKey key, byte[] ciphertext);
}
