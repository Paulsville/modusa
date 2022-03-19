/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa.fingerprint;

import org.whispersystems.modusa.IdentityKey;
import org.whispersystems.modusa.ratchet.AuthKey;
import org.whispersystems.modusa.util.ByteUtil;
import org.whispersystems.modusa.util.IdentityKeyComparator;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
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
   * @param localAuthKeys The client's authentication key object.
   * @param remoteAuthKeys The remote party's authentication key object.
   * @param chainedHash A MoDUSA chaining hash.
   * @param createForLastEpoch Whether to create the key for the current or last epoch. Creates for (i-1)th epoch if true,
   *                           otherwise creates for current epoch.
   * @return A unique fingerprint for this conversation.
   */
  @Override
  public Fingerprint createFor(int version,
                               final AuthKey localAuthKeys,
                               final AuthKey remoteAuthKeys,
                               final byte[] chainedHash,
                               boolean createForLastEpoch)
  {
    byte[] localAuthKey = createForLastEpoch ? localAuthKeys.getLastKeyBytes() : localAuthKeys.getKeyBytes();
    byte[] remoteAuthKey = createForLastEpoch ? remoteAuthKeys.getLastKeyBytes() : remoteAuthKeys.getKeyBytes();

    byte[] localFingerprint  = getFingerprint(iterations, localAuthKey, chainedHash);
    byte[] remoteFingerprint = getFingerprint(iterations, remoteAuthKey, chainedHash);

    DisplayableFingerprint displayableFingerprint = new DisplayableFingerprint(localFingerprint,
            remoteFingerprint);

    ScannableFingerprint   scannableFingerprint   = new ScannableFingerprint(version,
            localFingerprint,
            remoteFingerprint);

    return new Fingerprint(displayableFingerprint, scannableFingerprint);
  }

  /**
   * Generate a scannable and displayable fingerprint for logical identities that have multiple
   * physical keys.
   *
   * Do not trust the output of this unless you've been through the device consistency process
   * for the provided localIdentityKeys.
   *
   * @param version The version of fingerprint you are generating.
   * @return A unique fingerprint for this conversation.
   */
  public Fingerprint createFor(int version,
                               List<AuthKey> localAuthKeys,
                               List<AuthKey> remoteAuthKeys,
                               byte[] chainedHash,
                               boolean createForLastEpoch)
  {
    return createFor(version, localAuthKeys.get(localAuthKeys.size()-1), localAuthKeys.get(localAuthKeys.size()-1), chainedHash, createForLastEpoch);
  }

  private byte[] getFingerprint(int iterations, byte[] authKey, byte[] chainedHash) {
    try {
      MessageDigest digest    = MessageDigest.getInstance("SHA-512");
      byte[]        hash      = ByteUtil.combine(authKey, chainedHash, ByteUtil.shortToByteArray(FINGERPRINT_VERSION));

      for (int i=0;i<iterations;i++) {
        digest.update(hash);
        hash = digest.digest(authKey);
      }

      Mac mac = Mac.getInstance("HmacSHA256");
      mac.init(new SecretKeySpec(authKey, "HmacSHA256"));

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
