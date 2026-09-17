package com.meridian.pay.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * PAY-001 (harness §5.1 / §7.1 / §7.2): the transformation string is NOT a
 * literal anywhere in source -- it is a Spring property binding, resolved
 * per CFG-001 (Lock §4). An honest static tool must report `algorithm:
 * UNKNOWN` from source alone, and `INFERRED` (never KNOWN) once config-chain
 * resolution follows this binding to application.yml / overlays.
 */
@ConfigurationProperties(prefix = "pay.keywrap")
public class CryptoProperties {

    private String transformation;

    public String getTransformation() {
        return transformation;
    }

    public void setTransformation(String transformation) {
        this.transformation = transformation;
    }
}
