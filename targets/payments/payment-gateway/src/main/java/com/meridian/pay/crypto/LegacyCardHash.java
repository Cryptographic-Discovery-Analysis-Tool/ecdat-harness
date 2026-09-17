package com.meridian.pay.crypto;

import java.security.MessageDigest;

/**
 * TRAP-01 (harness §7.3): MD5, unreachable -- no class in this fixture
 * constructs or calls LegacyCardHash. Correct behaviour: a finding is
 * allowed (the call site exists), but reachable = UNKNOWN/false, and the
 * asset must NOT be raised to "in use" in the risk queue.
 *
 * Deliberately not a Spring bean (no @Component/@Service) and not
 * referenced from anywhere else in this fixture -- that absence of any
 * caller is the point of the trap.
 */
public final class LegacyCardHash {

    private LegacyCardHash() {
    }

    public static byte[] hash(byte[] cardNumber) throws Exception {
        MessageDigest md = MessageDigest.getInstance("MD5");
        return md.digest(cardNumber);
    }
}
