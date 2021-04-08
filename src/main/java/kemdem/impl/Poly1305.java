/*
 * Copyright 2021 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

package kemdem.impl;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;

final class Poly1305 {
    private static final BigInteger CLAMP = new BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16);
    public static final BigInteger P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5));

    static byte[] compute(byte[] key, byte[] data) {
        if (key.length != 32) { throw new IllegalArgumentException(); }

        var r = littleEndian(Arrays.copyOfRange(key, 0, 16));
        var s = littleEndian(Arrays.copyOfRange(key, 16, 32));
        r = r.and(CLAMP);

        var a = BigInteger.ZERO;
        for (int i = 0; i < data.length; i += 16) {
            var chunk = Arrays.copyOfRange(data, i, i + 17);
            var endIndex = Math.min(16, data.length - i);
            chunk[endIndex] = 1;
            a = a.add(littleEndian(chunk)).multiply(r).mod(P);
        }
        a = a.add(s);

        return Arrays.copyOf(Utils.reverse(a.toByteArray()), 16);
    }

    static BigInteger littleEndian(byte[] data) {
        return new BigInteger(1, Utils.reverse(data));
    }

    static boolean verify(byte[] key, byte[] data, byte[] tag) {
        return MessageDigest.isEqual(compute(key, data), tag);
    }
}
