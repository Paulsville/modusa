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
import org.whispersystems.modusa.kdf.HKDF;
import org.whispersystems.modusa.kdf.HKDFv3;
import org.whispersystems.modusa.protocol.CiphertextMessage;
import org.whispersystems.modusa.state.SessionState;
import org.whispersystems.modusa.util.ByteUtil;
import org.whispersystems.modusa.util.Triplet;
import org.whispersystems.modusa.util.guava.Optional;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.util.Arrays;

public class RatchetingSession {

  public static void initializeSession(SessionState sessionState, SymmetricSignalProtocolParameters parameters)
      throws InvalidKeyException, NoSuchAlgorithmException
  {
    if (isAlice(parameters.getOurBaseKey().getPublicKey(), parameters.getTheirBaseKey())) {
      AliceSignalProtocolParameters.Builder aliceParameters = AliceSignalProtocolParameters.newBuilder();

      aliceParameters.setOurBaseKey(parameters.getOurBaseKey())
                     .setOurIdentityKey(parameters.getOurIdentityKey())
                     .setTheirRatchetKey(parameters.getTheirRatchetKey())
                     .setTheirIdentityKey(parameters.getTheirIdentityKey())
                     .setTheirSignedPreKey(parameters.getTheirBaseKey())
                     .setTheirOneTimePreKey(Optional.<ECPublicKey>absent());

      RatchetingSession.initializeSession(sessionState, aliceParameters.create());
    } else {
      BobSignalProtocolParameters.Builder bobParameters = BobSignalProtocolParameters.newBuilder();

      bobParameters.setOurIdentityKey(parameters.getOurIdentityKey())
                   .setOurRatchetKey(parameters.getOurRatchetKey())
                   .setOurSignedPreKey(parameters.getOurBaseKey())
                   .setOurOneTimePreKey(Optional.<ECKeyPair>absent())
                   .setTheirBaseKey(parameters.getTheirBaseKey())
                   .setTheirIdentityKey(parameters.getTheirIdentityKey());

      RatchetingSession.initializeSession(sessionState, bobParameters.create());
    }
  }

  public static void initializeSession(SessionState sessionState, AliceSignalProtocolParameters parameters)
      throws InvalidKeyException, NoSuchAlgorithmException
  {
    try {
      sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
      sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
      sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

      ECKeyPair             sendingRatchetKey = Curve.generateKeyPair();
      ByteArrayOutputStream secrets           = new ByteArrayOutputStream();

      secrets.write(getDiscontinuityBytes());

      secrets.write(Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                             parameters.getOurIdentityKey().getPrivateKey()));
      secrets.write(Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                             parameters.getOurBaseKey().getPrivateKey()));
      secrets.write(Curve.calculateAgreement(parameters.getTheirSignedPreKey(),
                                             parameters.getOurBaseKey().getPrivateKey()));

      if (parameters.getTheirOneTimePreKey().isPresent()) {
        secrets.write(Curve.calculateAgreement(parameters.getTheirOneTimePreKey().get(),
                                               parameters.getOurBaseKey().getPrivateKey()));
      }

      DerivedKeys             derivedKeys  = calculateDerivedKeys(secrets.toByteArray(), sessionState.getAuthKey().getKeyBytes());
      Triplet<RootKey, ChainKey, AuthKey> sendingChain = derivedKeys.getRootKey().createChain(parameters.getTheirRatchetKey(), sendingRatchetKey);

      sessionState.addReceiverChain(parameters.getTheirRatchetKey(), derivedKeys.getChainKey());
      sessionState.setSenderChain(sendingRatchetKey, sendingChain.second());
      sessionState.setRootKey(sendingChain.first());

      sessionState.setAuthKey(derivedKeys.getAuthKey());

      byte[] initialHash;

      if(parameters.getTheirOneTimePreKey().isPresent()) {
        initialHash = genInitialHash(parameters.getTheirSignedPreKey().serialize(),
                parameters.getTheirOneTimePreKey().get().serialize(),
                parameters.getOurIdentityKey().getPublicKey().serialize(),
                parameters.getTheirIdentityKey().getPublicKey().serialize());
      } else {
        initialHash = genInitialHash(parameters.getTheirSignedPreKey().serialize(),
                parameters.getOurIdentityKey().getPublicKey().serialize(),
                parameters.getTheirIdentityKey().getPublicKey().serialize());
      }

      sessionState.setLastFprintHash(advanceHash(initialHash, parameters.getTheirRatchetKey().serialize()));
      sessionState.setFprintHash(advanceHash(sessionState.getLastFprintHash(), sendingRatchetKey.getPublicKey().serialize()));

    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  public static void initializeSession(SessionState sessionState, BobSignalProtocolParameters parameters)
      throws InvalidKeyException, NoSuchAlgorithmException
  {

    try {
      sessionState.setSessionVersion(CiphertextMessage.CURRENT_VERSION);
      sessionState.setRemoteIdentityKey(parameters.getTheirIdentityKey());
      sessionState.setLocalIdentityKey(parameters.getOurIdentityKey().getPublicKey());

      ByteArrayOutputStream secrets = new ByteArrayOutputStream();

      secrets.write(getDiscontinuityBytes());

      secrets.write(Curve.calculateAgreement(parameters.getTheirIdentityKey().getPublicKey(),
                                             parameters.getOurSignedPreKey().getPrivateKey()));
      secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                             parameters.getOurIdentityKey().getPrivateKey()));
      secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                             parameters.getOurSignedPreKey().getPrivateKey()));

      if (parameters.getOurOneTimePreKey().isPresent()) {
        secrets.write(Curve.calculateAgreement(parameters.getTheirBaseKey(),
                                               parameters.getOurOneTimePreKey().get().getPrivateKey()));
      }

      DerivedKeys derivedKeys = calculateDerivedKeys(secrets.toByteArray(), sessionState.getAuthKey().getKeyBytes());

      sessionState.setSenderChain(parameters.getOurRatchetKey(), derivedKeys.getChainKey());
      sessionState.setRootKey(derivedKeys.getRootKey());
      sessionState.setAuthKey(derivedKeys.getAuthKey());

      byte[] initialHash;

      if(parameters.getOurOneTimePreKey().isPresent()) {
        initialHash = genInitialHash(parameters.getOurSignedPreKey().getPublicKey().serialize(),
                parameters.getOurOneTimePreKey().get().getPublicKey().serialize(),
                parameters.getTheirIdentityKey().getPublicKey().serialize(),
                parameters.getOurIdentityKey().getPublicKey().serialize());
      } else {
        initialHash = genInitialHash(parameters.getOurSignedPreKey().getPublicKey().serialize(),
                parameters.getTheirIdentityKey().getPublicKey().serialize(),
                parameters.getOurIdentityKey().getPublicKey().serialize());
      }

      sessionState.setLastFprintHash(initialHash);
      sessionState.setFprintHash(advanceHash(initialHash, parameters.getOurRatchetKey().getPublicKey().serialize()));

    } catch (IOException e) {
      throw new AssertionError(e);
    }
  }

  private static byte[] getDiscontinuityBytes() {
    byte[] discontinuity = new byte[32];
    Arrays.fill(discontinuity, (byte) 0xFF);
    return discontinuity;
  }

  private static DerivedKeys calculateDerivedKeys(byte[] masterSecret, byte[] lastAuthKey) throws InvalidKeyException {
    HKDF     kdf                = new HKDFv3();
    byte[]   derivedSecretBytes = kdf.deriveSecrets(masterSecret, "WhisperText".getBytes(), 96);
    byte[][] derivedSecrets;
    try {
      derivedSecrets = ByteUtil.split(derivedSecretBytes, 32, 32, 32);
    } catch(ParseException e) {
      throw new InvalidKeyException();
    }

    return new DerivedKeys(new RootKey(kdf, derivedSecrets[0]),
                           new ChainKey(kdf, derivedSecrets[1], 0),
                           new AuthKey(derivedSecrets[2], lastAuthKey, 0));
  }

  private static byte[] genInitialHash(byte[] preKey, byte[] otpk, byte[] idpkA, byte[] idpkB) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] combined = ByteUtil.combine(preKey, otpk, idpkA, idpkB);

    return digest.digest(combined);
  }

  private static byte[] genInitialHash(byte[] preKey, byte[] idpkA, byte[] idpkB) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] combined = ByteUtil.combine(preKey, idpkA, idpkB);

    return digest.digest(combined);
  }

  private static byte[] advanceHash(byte[] hash, byte[] rcpk) throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-512");
    byte[] combined = ByteUtil.combine(hash, rcpk);

    return digest.digest(combined);
  }

  private static boolean isAlice(ECPublicKey ourKey, ECPublicKey theirKey) {
    return ourKey.compareTo(theirKey) < 0;
  }

  private static class DerivedKeys {
    private final RootKey   rootKey;
    private final ChainKey  chainKey;
    private final AuthKey   authKey;

    private DerivedKeys(RootKey rootKey, ChainKey chainKey, AuthKey authKey) {
      this.rootKey   = rootKey;
      this.chainKey  = chainKey;
      this.authKey = authKey;
    }

    public RootKey getRootKey() {
      return rootKey;
    }

    public ChainKey getChainKey() {
      return chainKey;
    }

    public AuthKey getAuthKey() { return authKey; }
  }
}
