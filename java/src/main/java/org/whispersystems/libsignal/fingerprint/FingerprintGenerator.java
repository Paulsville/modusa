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
  Fingerprint createFor(int version,
                               AuthKey aKey,
                               AuthKey remoteAKey,
                               byte[] hash,
                               boolean genPrevKey);
}
