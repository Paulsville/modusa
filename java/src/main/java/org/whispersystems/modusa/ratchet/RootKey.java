/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa.ratchet;

import org.whispersystems.modusa.InvalidKeyException;
import org.whispersystems.modusa.ecc.Curve;
import org.whispersystems.modusa.ecc.ECKeyPair;
import org.whispersystems.modusa.ecc.ECPublicKey;
import org.whispersystems.modusa.kdf.DerivedRootSecrets;
import org.whispersystems.modusa.kdf.HKDF;
import org.whispersystems.modusa.util.Triplet;

public class RootKey {

  private final HKDF   kdf;
  private final byte[] key;

  public RootKey(HKDF kdf, byte[] key) {
    this.kdf = kdf;
    this.key = key;
  }

  public byte[] getKeyBytes() {
    return key;
  }

  public Triplet<RootKey, ChainKey, AuthKey> createChain(ECPublicKey theirRatchetKey, ECKeyPair ourRatchetKey)
      throws InvalidKeyException
  {
    byte[]             sharedSecret       = Curve.calculateAgreement(theirRatchetKey, ourRatchetKey.getPrivateKey());
    byte[]             derivedSecretBytes = kdf.deriveSecrets(sharedSecret, key, "WhisperRatchet".getBytes(), DerivedRootSecrets.SIZE);
    DerivedRootSecrets derivedSecrets     = new DerivedRootSecrets(derivedSecretBytes);

    RootKey  newRootKey  = new RootKey(kdf, derivedSecrets.getRootKey());
    ChainKey newChainKey = new ChainKey(kdf, derivedSecrets.getChainKey(), 0);
    AuthKey newAuthKey = new AuthKey(derivedSecrets.getAuthKey(), derivedSecrets.getAuthKey(), 0);

    return new Triplet<>(newRootKey, newChainKey, newAuthKey);
  }
}
