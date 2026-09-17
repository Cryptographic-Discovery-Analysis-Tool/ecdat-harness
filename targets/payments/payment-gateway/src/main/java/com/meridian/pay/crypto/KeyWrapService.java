package com.meridian.pay.crypto;

import com.meridian.pay.config.CryptoProperties;
import java.security.GeneralSecurityException;
import java.security.PublicKey;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import org.springframework.stereotype.Service;

/**
 * PAY-001 (harness §5.1, the headline hard case): algorithm is NOT a literal
 * here -- it comes from application.yml (or an overlay). WRAP_MODE with a
 * PublicKey means the transformation must be asymmetric (harness §14 A3).
 */
@Service
public class KeyWrapService {

    private final CryptoProperties props;

    public KeyWrapService(CryptoProperties props) {
        this.props = props;
    }

    public byte[] wrap(SecretKey dek, PublicKey kek) throws GeneralSecurityException {
        Cipher c = Cipher.getInstance(props.getTransformation());
        c.init(Cipher.WRAP_MODE, kek);
        return c.wrap(dek);
    }
}
