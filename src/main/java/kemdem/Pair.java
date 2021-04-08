package kemdem;

/**
 * Represents a pair of elements (product type).
 *
 * @param <A> the type of the first element.
 * @param <B> the type of the second element.
 */
public final class Pair<A, B> {
    public final A a;
    public final B b;

    public Pair(A a, B b) {
        this.a = a;
        this.b = b;
    }
}
