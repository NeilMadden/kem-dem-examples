package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import org.testng.annotations.Test;

public class Poly1305Test {

    @Test
    public void testCases() {
        var key = hexToBytes("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
        var data = "Cryptographic Forum Research Group".getBytes(StandardCharsets.UTF_8);
        var expectedTag = hexToBytes(" a8:06:1d:c1:30:51:36:c6:c2:2b:8b:af:0c:01:27:a9");

        assertThat(Poly1305.compute(key, data)).isEqualTo(expectedTag);
        assertThat(Poly1305.verify(key, data, expectedTag)).isTrue();
    }

    @Test
    public void testEmptyInput() {
        var key = hexToBytes("85:d6:be:78:57:55:6d:33:7f:44:52:fe:42:d5:06:a8:01:03:80:8a:fb:0d:b2:fd:4a:bf:f6:af:41:49:f5:1b");
        assertThat(Poly1305.compute(key, new byte[0])).isEqualTo(Arrays.copyOfRange(key, 16, 32));
    }

    static byte[] hexToBytes(String hex) {
        var i = new BigInteger(hex.replaceAll("\\s+|:", ""), 16);
        var bytes = i.toByteArray();
        if (bytes[0] == 0) {
            bytes = Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }
}