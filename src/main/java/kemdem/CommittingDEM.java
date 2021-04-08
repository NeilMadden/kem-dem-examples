/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

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
