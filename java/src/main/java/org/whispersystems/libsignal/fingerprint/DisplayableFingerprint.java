/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.util.ByteUtil;

public class DisplayableFingerprint {

  private final String fprintNumbers;

  DisplayableFingerprint(byte[] fprint)
  {
    this.fprintNumbers  = getDisplayStringFor(fprint);
  }

  private String getDisplayStringFor(byte[] fingerprint) {
    return getEncodedChunk(fingerprint, 0)  +
           getEncodedChunk(fingerprint, 5)  +
           getEncodedChunk(fingerprint, 10) +
           getEncodedChunk(fingerprint, 15) +
           getEncodedChunk(fingerprint, 20) +
           getEncodedChunk(fingerprint, 25);
  }

  private String getEncodedChunk(byte[] hash, int offset) {
    long chunk = ByteUtil.byteArray5ToLong(hash, offset) % 100000;
    return String.format("%05d", chunk);
  }

}
