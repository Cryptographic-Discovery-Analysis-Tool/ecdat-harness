package com.meridian.pay.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.stereotype.Service;

/**
 * PAY-002 (harness §5.1 / §7.2): literal Mac.getInstance("HmacSHA256") ->
 * KNOWN at source level. Purpose (webhook integrity) is not locally visible
 * from a MAC call alone -- "MAC => integrity" is an INFERENCE, per harness
 * §7.2's own expected-observation column ("purpose UNKNOWN from Semgrep").
 */
@Service
public class WebhookSigner {

    public byte[] sign(byte[] payload, byte[] key) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(payload);
    }
}
