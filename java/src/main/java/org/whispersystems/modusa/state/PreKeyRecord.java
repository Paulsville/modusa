/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa.state;

import com.google.protobuf.ByteString;

import org.whispersystems.modusa.InvalidKeyException;
import org.whispersystems.modusa.ecc.Curve;
import org.whispersystems.modusa.ecc.ECKeyPair;
import org.whispersystems.modusa.ecc.ECPrivateKey;
import org.whispersystems.modusa.ecc.ECPublicKey;

import java.io.IOException;

import static org.whispersystems.modusa.state.StorageProtos.PreKeyRecordStructure;

public class PreKeyRecord {

  private PreKeyRecordStructure structure;

  public PreKeyRecord(int id, ECKeyPair keyPair) {
    this.structure = PreKeyRecordStructure.newBuilder()
                                          .setId(id)
                                          .setPublicKey(ByteString.copyFrom(keyPair.getPublicKey()
                                                                                   .serialize()))
                                          .setPrivateKey(ByteString.copyFrom(keyPair.getPrivateKey()
                                                                                    .serialize()))
                                          .build();
  }

  public PreKeyRecord(byte[] serialized) throws IOException {
    this.structure = PreKeyRecordStructure.parseFrom(serialized);
  }

  public int getId() {
    return this.structure.getId();
  }

  public ECKeyPair getKeyPair() {
    try {
      ECPublicKey publicKey = Curve.decodePoint(this.structure.getPublicKey().toByteArray(), 0);
      ECPrivateKey privateKey = Curve.decodePrivatePoint(this.structure.getPrivateKey().toByteArray());

      return new ECKeyPair(publicKey, privateKey);
    } catch (InvalidKeyException e) {
      throw new AssertionError(e);
    }
  }

  public byte[] serialize() {
    return this.structure.toByteArray();
  }
}
