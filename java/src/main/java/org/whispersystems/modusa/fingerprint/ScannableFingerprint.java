/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa.fingerprint;

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;

import org.whispersystems.modusa.util.ByteUtil;
import org.whispersystems.modusa.fingerprint.FingerprintProtos.*;

import java.security.MessageDigest;

public class ScannableFingerprint {

  private final int                  version;
  private final CombinedFingerprints fingerprints;

  ScannableFingerprint(int version, byte[] localFingerprintData, byte[] remoteFingerprintData)
  {
    LogicalFingerprint localFingerprint = LogicalFingerprint.newBuilder()
            .setContent(ByteString.copyFrom(ByteUtil.trim(localFingerprintData, 32)))
            .build();

    LogicalFingerprint remoteFingerprint = LogicalFingerprint.newBuilder()
            .setContent(ByteString.copyFrom(ByteUtil.trim(remoteFingerprintData, 32)))
            .build();

    this.version      = version;
    this.fingerprints = CombinedFingerprints.newBuilder()
                                            .setVersion(version)
                                            .setLocalFingerprint(localFingerprint)
                                            .setRemoteFingerprint(remoteFingerprint)
                                            .build();
  }

  /**
   * @return A byte string to be displayed in a QR code.
   */
  public byte[] getSerialized() {
    return fingerprints.toByteArray();
  }

  /**
   * Compare a scanned QR code with what we expect.
   *
   * @param scannedFingerprintData The scanned data
   * @return True if matching, otherwise false.
   * @throws FingerprintVersionMismatchException if the scanned fingerprint is the wrong version.
   */
  public boolean compareTo(byte[] scannedFingerprintData)
      throws FingerprintVersionMismatchException,
             FingerprintParsingException
  {
    try {
      CombinedFingerprints scanned = CombinedFingerprints.parseFrom(scannedFingerprintData);

      if (!scanned.hasLocalFingerprint() ||
          !scanned.hasVersion() || scanned.getVersion() != version)
      {
        throw new FingerprintVersionMismatchException(scanned.getVersion(), version);
      }

      return MessageDigest.isEqual(fingerprints.getLocalFingerprint().getContent().toByteArray(), scanned.getRemoteFingerprint().getContent().toByteArray()) &&
             MessageDigest.isEqual(fingerprints.getRemoteFingerprint().getContent().toByteArray(), scanned.getLocalFingerprint().getContent().toByteArray());
    } catch (InvalidProtocolBufferException e) {
      throw new FingerprintParsingException(e);
    }
  }
}
