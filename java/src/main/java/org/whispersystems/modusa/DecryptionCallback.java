/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa;

public interface DecryptionCallback {
  public void handlePlaintext(byte[] plaintext);
}