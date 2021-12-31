/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.kdf;

import org.whispersystems.libsignal.util.ByteUtil;
import sun.jvm.hotspot.utilities.AssertionFailure;

import java.text.ParseException;

public class DerivedRootSecrets {

  public static final int SIZE = 96;

  private final byte[] rootKey;
  private final byte[] chainKey;
  private final byte[] authKey;

  public DerivedRootSecrets(byte[] okm) {
    byte[][] keys;
    try {
      keys = ByteUtil.split(okm, 32, 32, 32);
    } catch(ParseException e) {
      keys = ByteUtil.split(okm, 32, 32);
    }
    this.rootKey  = keys[0];
    this.chainKey = keys[1];
    if(keys.length > 2) {
      this.authKey = keys[2];
    } else {
      this.authKey = new byte[] {};
    }
  }

  public byte[] getRootKey() {
    return rootKey;
  }

  public byte[] getChainKey() {
    return chainKey;
  }

  public byte[] getAuthKey() { return authKey; }

}
