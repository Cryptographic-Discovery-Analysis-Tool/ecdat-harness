package com.meridian.pay.crypto;

import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/**
 * PAY-003 (harness §7.2): AES-256-GCM literal, tokenisation. KNOWN at source
 * level -- literal transformation string, no config indirection.
 */
@Service
public class TokenVault {

    private static final int GCM_TAG_BITS = 128;
    private static final int GCM_IV_BYTES = 12;

    public byte[] tokenize(byte[] plaintext, byte[] key256) throws Exception {
        byte[] iv = new byte[GCM_IV_BYTES];
        new SecureRandom().nextBytes(iv);
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key256, "AES"), new GCMParameterSpec(GCM_TAG_BITS, iv));
        return c.doFinal(plaintext);
    }
}
