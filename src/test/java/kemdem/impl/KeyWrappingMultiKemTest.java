package kemdem.impl;

import static org.assertj.core.api.Assertions.assertThat;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import kemdem.MultiKem;

public class KeyWrappingMultiKemTest {

    private MultiKem kem;

    @BeforeMethod
    public void setup() {
        kem = new KeyWrappingMultiKem(new EcdhKem());
    }

    @Test
    public void testBasicFunctionality() {
        // Given
        var alice = kem.keyGen();
        var bob = kem.keyGen();
        var charlie = kem.keyGen();

        // When
        var encapKey = kem.encap(alice.getPublic(), bob.getPublic(), charlie.getPublic());

        var aliceKey = kem.decap(alice.getPrivate(), encapKey.b).orElseThrow();
        var bobKey = kem.decap(bob.getPrivate(), encapKey.b).orElseThrow();
        var charlieKey = kem.decap(charlie.getPrivate(), encapKey.b).orElseThrow();

        // Then
        assertThat(aliceKey).isEqualTo(encapKey.a).isEqualTo(bobKey).isEqualTo(charlieKey);
    }

}