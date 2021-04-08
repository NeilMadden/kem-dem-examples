package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.KEM;

public class RsaKemTest {

    private KEM rsaKem;

    @BeforeMethod
    public void setup() {
        rsaKem = new RsaKem();
    }

    @Test
    public void testBasicKemFunctionality() throws Exception {
        // Given
        var recipientKeys = rsaKem.keyGen();

        // When
        var key = rsaKem.encap(recipientKeys.getPublic());
        var decapKey = rsaKem.decap(recipientKeys.getPrivate(), key.b).orElseThrow();

        // Then
        assertThat(decapKey).isEqualTo(key.a);
    }

    @Test
    public void testTiming() {
        var keys = rsaKem.keyGen();

        var ek = rsaKem.encap(keys.getPublic()).b;

        SecretKey key = null;
        // Warmup
        for (int i = 0; i < 1000; ++i) {
            key = rsaKem.decap(keys.getPrivate(), ek).orElseThrow();
        }

        // Timing run
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; ++i) {
            key = rsaKem.decap(keys.getPrivate(), ek).orElseThrow();
        }
        long end = System.currentTimeMillis();
        System.out.println(key.toString());
        System.out.println("Time per decapsulation: " + (end - start) / 10000.0d + "ms");

    }
}