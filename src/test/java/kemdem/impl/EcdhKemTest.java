package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import java.security.KeyPair;

import javax.crypto.SecretKey;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.KEM;
import kemdem.Pair;

public class EcdhKemTest {

    private KEM ecdhKem;

    @BeforeMethod
    public void setup() {
        ecdhKem = new EcdhKem();
    }

    @Test
    public void testBasicKemFunctionality() {
        // Given
        KeyPair recipientKeys = ecdhKem.keyGen();

        // When
        Pair<SecretKey, byte[]> key = ecdhKem.encap(recipientKeys.getPublic());
        SecretKey decapKey = ecdhKem.decap(recipientKeys.getPrivate(), key.b).orElseThrow();

        // Then
        assertThat(decapKey).isEqualTo(key.a);
    }

    @Test
    public void testSpeed() {
        var keys = ecdhKem.keyGen();

        SecretKey key = null;
        // Warmup
        for (int i = 0; i < 1000; ++i) {
            key = ecdhKem.encap(keys.getPublic()).a;
        }

        // Timing run
        long start = System.currentTimeMillis();
        for (int i = 0; i < 10000; ++i) {
            key = ecdhKem.encap(keys.getPublic()).a;
        }
        long end = System.currentTimeMillis();
        System.out.println(key.toString());
        System.out.println("Time per encapsulation: " + (end - start) / 10000.0d + "ms");

    }
}