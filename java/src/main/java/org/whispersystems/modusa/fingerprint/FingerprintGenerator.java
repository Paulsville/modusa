/**
 * Copyright (C) 2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa.fingerprint;

import org.whispersystems.modusa.ratchet.AuthKey;

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
