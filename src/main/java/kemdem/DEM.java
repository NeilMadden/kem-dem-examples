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
 * This interface represents the original one-time secure DEM.
 */
public interface DEM {
    SecretKey keyGen();
    byte[] enc(SecretKey key, byte[] message);
    byte[] dec(SecretKey key, byte[] ciphertext);
}
