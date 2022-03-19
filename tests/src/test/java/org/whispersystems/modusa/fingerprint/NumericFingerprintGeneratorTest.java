package org.whispersystems.modusa.fingerprint;

import junit.framework.TestCase;

import org.whispersystems.modusa.ecc.Curve;
import org.whispersystems.modusa.ecc.ECKeyPair;
import org.whispersystems.modusa.ratchet.AuthKey;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class NumericFingerprintGeneratorTest extends TestCase {

  private static final int    VERSION                     = 1;
  private static final byte[] ALICE_IDENTITY              = {(byte) 0x05, (byte) 0x06, (byte) 0x86, (byte) 0x3b, (byte) 0xc6, (byte) 0x6d, (byte) 0x02, (byte) 0xb4, (byte) 0x0d, (byte) 0x27, (byte) 0xb8, (byte) 0xd4, (byte) 0x9c, (byte) 0xa7, (byte) 0xc0, (byte) 0x9e, (byte) 0x92, (byte) 0x39, (byte) 0x23, (byte) 0x6f, (byte) 0x9d, (byte) 0x7d, (byte) 0x25, (byte) 0xd6, (byte) 0xfc, (byte) 0xca, (byte) 0x5c, (byte) 0xe1, (byte) 0x3c, (byte) 0x70, (byte) 0x64, (byte) 0xd8, (byte) 0x68};
  private static final byte[] ALICE_LAST_IDENTITY         = {};
  private static final byte[] BOB_IDENTITY                = {(byte) 0x05, (byte) 0xf7, (byte) 0x81, (byte) 0xb6, (byte) 0xfb, (byte) 0x32, (byte) 0xfe, (byte) 0xd9, (byte) 0xba, (byte) 0x1c, (byte) 0xf2, (byte) 0xde, (byte) 0x97, (byte) 0x8d, (byte) 0x4d, (byte) 0x5d, (byte) 0xa2, (byte) 0x8d, (byte) 0xc3, (byte) 0x40, (byte) 0x46, (byte) 0xae, (byte) 0x81, (byte) 0x44, (byte) 0x02, (byte) 0xb5, (byte) 0xc0, (byte) 0xdb, (byte) 0xd9, (byte) 0x6f, (byte) 0xda, (byte) 0x90, (byte) 0x7b};
  private static final byte[] BOB_LAST_IDENTITY           = {};
  private static final byte[] CHAINED_HASH = "0f588be3d1c4e72fd4f65d2b451ccecf9ab3704c58846283b04dba930b111763".getBytes(StandardCharsets.UTF_8);
  private static final byte[] MISMATCHED_HASH = "bcb154d7c9ed6b96483b92fdfea1d587a8f4f3fadff89ccf2b0ab8135d9b5fc3".getBytes(StandardCharsets.UTF_8);
  private static final String DISPLAYABLE_FINGERPRINT     = "730872997323792922639733228841921866086491721601358927692439";
  private static final byte[] ALICE_SCANNABLE_FINGERPRINT = new byte[] {8, 1, 18, 34, 10, 32, -53, 62, 114, -48, -1, -54, -30, 25, -73, 117, 86, 84, 20, -102, 48, 4, 91, -40, -98, -57, -9, -77, -21, -51, 116, -21, -77, -77, -16, -23, -90, 97, 26, 34, 10, 32, 8, 107, -12, 3, -102, 41, 13, 85, 106, -32, 0, 50, 104, 59, 73, 43, 24, 53, -101, -121, 118, -64, -73, 116, 92, -69, -29, -49, 55, 23, 98, 101};
  private static final byte[] BOB_SCANNABLE_FINGERPRINT = new byte[] {8, 1, 18, 34, 10, 32, 8, 107, -12, 3, -102, 41, 13, 85, 106, -32, 0, 50, 104, 59, 73, 43, 24, 53, -101, -121, 118, -64, -73, 116, 92, -69, -29, -49, 55, 23, 98, 101, 26, 34, 10, 32, -53, 62, 114, -48, -1, -54, -30, 25, -73, 117, 86, 84, 20, -102, 48, 4, 91, -40, -98, -57, -9, -77, -21, -51, 116, -21, -77, -77, -16, -23, -90, 97};

  public void testVectors() throws Exception {

    AuthKey aliceAuthKey = new AuthKey(ALICE_IDENTITY, ALICE_LAST_IDENTITY, 0);
    AuthKey bobAuthKey = new AuthKey(BOB_IDENTITY, BOB_LAST_IDENTITY, 0);

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(5200);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION,
                                                                       aliceAuthKey,
                                                                       bobAuthKey,
                                                                       CHAINED_HASH,
                                                                       false);

    Fingerprint                 bobFingerprint = generator.createFor(VERSION,
                                                                       bobAuthKey,
                                                                       aliceAuthKey,
                                                                       CHAINED_HASH,
                                                        false);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT);
    assertEquals(bobFingerprint.getDisplayableFingerprint().getDisplayText(), DISPLAYABLE_FINGERPRINT);

    assertTrue(Arrays.equals(aliceFingerprint.getScannableFingerprint().getSerialized(), ALICE_SCANNABLE_FINGERPRINT));
    assertTrue(Arrays.equals(bobFingerprint.getScannableFingerprint().getSerialized(), BOB_SCANNABLE_FINGERPRINT));
  }

  public void testMatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair aliceLastKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair bobLastKeyPair = Curve.generateKeyPair();

    AuthKey aliceAuthKey = new AuthKey(aliceKeyPair.getPublicKey().serialize(), aliceLastKeyPair.getPublicKey().serialize(), 0);
    AuthKey bobAuthKey = new AuthKey(bobKeyPair.getPublicKey().serialize(), bobLastKeyPair.getPublicKey().serialize(), 0);

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION,
                                                                       aliceAuthKey,
                                                                       bobAuthKey,
                                                                       CHAINED_HASH,
                                                        false);

    Fingerprint                 bobFingerprint = generator.createFor(VERSION,
                                                                       bobAuthKey,
                                                                       aliceAuthKey,
                                                                       CHAINED_HASH,
                                                        false);

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                 bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertTrue(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertTrue(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));

    assertEquals(aliceFingerprint.getDisplayableFingerprint().getDisplayText().length(), 60);
  }

  public void testMismatchingFingerprints() throws FingerprintVersionMismatchException, FingerprintIdentifierMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair aliceLastKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair bobLastKeyPair   = Curve.generateKeyPair();
    ECKeyPair mitmKeyPair  = Curve.generateKeyPair();
    ECKeyPair mitmLastKeyPair  = Curve.generateKeyPair();

    AuthKey aliceAuthKey = new AuthKey(aliceKeyPair.getPublicKey().serialize(), aliceLastKeyPair.getPublicKey().serialize(), 0);
    AuthKey bobAuthKey = new AuthKey(bobKeyPair.getPublicKey().serialize(), bobLastKeyPair.getPublicKey().serialize(), 0);
    AuthKey mitmAuthKey = new AuthKey(mitmKeyPair.getPublicKey().serialize(), mitmLastKeyPair.getPublicKey().serialize(), 0);

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION,
                                                                       aliceAuthKey,
                                                                       mitmAuthKey,
            CHAINED_HASH,
                                                        false);

    Fingerprint                 bobFingerprint = generator.createFor(VERSION,
                                                                     bobAuthKey,
                                                                     aliceAuthKey,
            CHAINED_HASH,
                                                      false);

    assertNotSame(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                  bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

  public void testMismatchingIdentifiers() throws FingerprintVersionMismatchException, FingerprintParsingException {
    ECKeyPair aliceKeyPair = Curve.generateKeyPair();
    ECKeyPair aliceLastKeyPair = Curve.generateKeyPair();
    ECKeyPair bobKeyPair   = Curve.generateKeyPair();
    ECKeyPair bobLastKeyPair   = Curve.generateKeyPair();

    AuthKey aliceAuthKey = new AuthKey(aliceKeyPair.getPublicKey().serialize(), aliceLastKeyPair.getPublicKey().serialize(), 0);
    AuthKey bobAuthKey = new AuthKey(bobKeyPair.getPublicKey().serialize(), bobLastKeyPair.getPublicKey().serialize(), 0);

    NumericFingerprintGenerator generator        = new NumericFingerprintGenerator(1024);
    Fingerprint                 aliceFingerprint = generator.createFor(VERSION,
                                                                       aliceAuthKey,
                                                                       bobAuthKey,
                                                                       CHAINED_HASH,
                                                        false);

    Fingerprint                 bobFingerprint = generator.createFor(VERSION,
                                                                     bobAuthKey,
                                                                     aliceAuthKey,
                                                                     MISMATCHED_HASH,
                                                      false);

    assertNotSame(aliceFingerprint.getDisplayableFingerprint().getDisplayText(),
                  bobFingerprint.getDisplayableFingerprint().getDisplayText());

    assertFalse(aliceFingerprint.getScannableFingerprint().compareTo(bobFingerprint.getScannableFingerprint().getSerialized()));
    assertFalse(bobFingerprint.getScannableFingerprint().compareTo(aliceFingerprint.getScannableFingerprint().getSerialized()));
  }

}