package org.whispersystems.libsignal.util;

public class Triplet<T1, T2, T3> {
    private final T1 v1;
    private final T2 v2;
    private final T3 v3;

    public Triplet(T1 v1, T2 v2, T3 v3) {
        this.v1 = v1;
        this.v2 = v2;
        this.v3 = v3;
    }

    public T1 first(){
        return v1;
    }

    public T2 second(){
        return v2;
    }

    public T3 third() { return v3; }

    public boolean equals(Object o) {
        return o instanceof Triplet &&
                equal(((Triplet) o).first(), first()) &&
                equal(((Triplet) o).second(), second());
    }

    public int hashCode() {
        return first().hashCode() ^ second().hashCode() ^ third().hashCode();
    }

    private boolean equal(Object first, Object second) {
        if (first == null && second == null) return true;
        if (first == null || second == null) return false;
        return first.equals(second);
    }
}