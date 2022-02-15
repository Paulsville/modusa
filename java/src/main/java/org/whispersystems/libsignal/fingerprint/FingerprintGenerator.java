/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.libsignal.fingerprint;

import org.whispersystems.libsignal.IdentityKey;
import org.whispersystems.libsignal.ratchet.AuthKey;

import java.util.List;

public interface FingerprintGenerator {
  public Fingerprint createFor(int version,
                               AuthKey localAuthKey,
                               AuthKey remoteAuthKey,
                               byte[] chainedHash,
                               boolean createForLastEpoch);

  public Fingerprint createFor(int version,
                               List<AuthKey> localIdentityKey,
                               List<AuthKey> remoteIdentityKey,
                               byte[] chainedHash,
                               boolean createForLastEpoch);
}
