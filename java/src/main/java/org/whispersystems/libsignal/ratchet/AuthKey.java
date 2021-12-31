package org.whispersystems.libsignal.ratchet;

import org.whispersystems.libsignal.kdf.HKDF;

public class AuthKey {

    private final byte[] key;
    private final byte[] lastKey;
    private final int index;

    public AuthKey(byte[] key, byte[] lastKey, int index) {
        this.key = key;
        this.lastKey = lastKey;
        this.index = index;
    }

    public byte[] getKeyBytes() { return key; }
    public byte[] getLastKeyBytes() { return lastKey; }
    public int getIndex() { return index; }
}
