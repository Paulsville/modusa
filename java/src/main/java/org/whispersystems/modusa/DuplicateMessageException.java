/**
 * Copyright (C) 2014-2016 Open Whisper Systems
 *
 * Licensed according to the LICENSE file in this repository.
 */
package org.whispersystems.modusa;

public class DuplicateMessageException extends Exception {
  public DuplicateMessageException(String s) {
    super(s);
  }
}
