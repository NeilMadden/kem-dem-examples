package kemdem.impl;

import static java.nio.charset.StandardCharsets.UTF_8;

import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

public class X25519RKEMTest {

    private X25519RKEM kem;

    @BeforeMethod
    public void setup() {
        kem = new X25519RKEM();
    }

    @Test
    public void testBasicOperation() {
        var label = new byte[0];
        var alice = kem.keyGen();
        var bob = kem.keyGen();
        var dem = new HmacSivDEM();

        System.out.println("Creating message from Alice to Bob");
        var aliceState = kem.begin(alice.getPrivate(), bob.getPublic());
        var demKey = kem.key(aliceState);
        var ct1 = dem.enc(demKey, "Hello Bob!".getBytes(UTF_8), label);
        var stateAndEk = kem.authEncap(aliceState, ct1.b);
        aliceState = stateAndEk.a;
        var ek = stateAndEk.b;

        System.out.println("Bob receives message");
        var bobState = kem.begin(bob.getPrivate(), alice.getPublic());
        var stateAndKey = kem.authDecap(bobState, ek, ct1.b).orElseThrow();
        bobState = stateAndKey.a;
        demKey = stateAndKey.b;
        System.out.println(new String(dem.dec(demKey, ct1.a, label, ct1.b), UTF_8));

        System.out.println("Creating Bob's reply");
        demKey = kem.key(bobState);
        var ct2 = dem.enc(demKey, "Hello Alice!".getBytes(UTF_8), label);
        stateAndEk = kem.authEncap(bobState, ct2.b);
        bobState = stateAndEk.a;
        ek = stateAndEk.b;

        System.out.println("Alice decoding Bob's reply");
        stateAndKey = kem.authDecap(aliceState, ek, ct2.b).orElseThrow();
        aliceState = stateAndKey.a;
        demKey = stateAndKey.b;
        System.out.println(new String(dem.dec(demKey, ct2.a, label, ct2.b), UTF_8));

        System.out.println("Alice replies again");
        demKey = kem.key(aliceState);
        var ct3 = dem.enc(demKey, "Goodbye Bob!".getBytes(UTF_8), label);
        stateAndEk = kem.authEncap(aliceState, ct3.b);
        aliceState = stateAndEk.a;
        ek = stateAndEk.b;

        System.out.println("Bob receives Alice's reply");
        stateAndKey = kem.authDecap(bobState, ek, ct3.b).orElseThrow();
        bobState = stateAndKey.a;
        demKey = stateAndKey.b;
        System.out.println(new String(dem.dec(demKey, ct3.a, label, ct3.b), UTF_8));

        System.out.println("Bob replies a last time");
        demKey = kem.key(bobState);
        var ct4 = dem.enc(demKey, "Goodbye Alice!".getBytes(UTF_8), label);
        stateAndEk = kem.authEncap(bobState, ct4.b);
        ek = stateAndEk.b;

        System.out.println("Alice decrypts final reply");
        stateAndKey = kem.authDecap(aliceState, ek, ct4.b).orElseThrow();
        demKey = stateAndKey.b;
        System.out.println(new String(dem.dec(demKey, ct4.a, label, ct4.b), UTF_8));
    }
}