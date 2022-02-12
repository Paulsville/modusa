/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ratchet.AuthKey;
import org.whispersystems.libsignal.state.PreKeyBundle;
import org.whispersystems.libsignal.util.ByteUtil;
import org.whispersystems.libsignal.util.IdentityKeyComparator;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class NumericFingerprintGenerator implements FingerprintGenerator {

  private static final int FINGERPRINT_VERSION = 0;

  private final int iterations;

  /**
   * Construct a fingerprint generator for 60 digit numerics.
   *
   * @param iterations The number of internal iterations to perform in the process of
   *                   generating a fingerprint. This needs to be constant, and synchronized
   *                   across all clients.
   *
   *                   The higher the iteration count, the higher the security level:
   *
   *                   - 1024 ~ 109.7 bits
   *                   - 1400 > 110 bits
   *                   - 5200 > 112 bits
   */
  public NumericFingerprintGenerator(int iterations) {
    this.iterations = iterations;
  }

  /**
   * Generate a scannable and displayable fingerprint.
   *
   * @param version The version of fingerprint you are generating.
   * @param aKey Generated authentication keys from session state
   * @param hash Chaining hash from session state
   * @param genPrevKey When true, use (i-1)th key, otherwise use ith key
   * @return A unique fingerprint for this conversation.
   */
  public Fingerprint createFor(int version,
                               AuthKey aKey,
                               AuthKey bKey,
                               byte[] hash,
                               boolean genPrevKey)
  {
    byte[] fprint  = getFingerprint(iterations, aKey, hash, genPrevKey);

    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(fprint);

    ScannableFingerprint   scannableFingerprint   = new ScannableFingerprint(version, fprint);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }

  private byte[] getFingerprint(int iterations, AuthKey aKey,
                                byte[] hash, boolean genPrevKey) {
    try {
      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[] key = genPrevKey ? aKey.getLastKeyBytes() : aKey.getKeyBytes();

      byte[] data = ByteUtil.combine(hash, key);

      for (int i=0;i<iterations;i++) {
        digest.update(data);
        hash = digest.digest(data);
      }

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(key, "HmacSHA256"));

      return mac.doFinal(hash);

    } catch (NoSuchAlgorithmException | InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  private byte[] getLogicalKeyBytes(List<IdentityKey> identityKeys) {
    ArrayList<IdentityKey> sortedIdentityKeys = new ArrayList<>(identityKeys);
    Collections.sort(sortedIdentityKeys, new IdentityKeyComparator());

    ByteArrayOutputStream baos = new ByteArrayOutputStream();

    for (IdentityKey identityKey : sortedIdentityKeys) {
      byte[] publicKeyBytes = identityKey.getPublicKey().serialize();
      baos.write(publicKeyBytes, 0, publicKeyBytes.length);
    }

    return baos.toByteArray();
  }


}
