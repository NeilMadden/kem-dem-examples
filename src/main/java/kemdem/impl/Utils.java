package kemdem.impl;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

final class Utils {

    static byte[] sha256(byte[]...values) {
        try {
            var sha256 = MessageDigest.getInstance("SHA-256");
            for (byte[] input : values) {
                sha256.update(input);
            }
            return sha256.digest();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not implemented!");
        }
    }

    static byte[] trimSignByte(byte[] n) {
        // BigInteger.toByteArray() returns a signed representation - remove the leading zero byte if necessary
        if (n[0] == 0) {
            return Arrays.copyOfRange(n, 1, n.length);
        }
        return n;
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] combined = new byte[a.length + b.length];
        System.arraycopy(a, 0, combined, 0, a.length);
        System.arraycopy(b, 0, combined, a.length, b.length);
        return combined;
    }

    static byte[] reverse(byte[] xs) {
        for (int i = 0; i < xs.length/2; ++i) {
            byte tmp = xs[i];
            xs[i] = xs[xs.length - i - 1];
            xs[xs.length - i - 1] = tmp;
        }
        return xs;
    }
}
