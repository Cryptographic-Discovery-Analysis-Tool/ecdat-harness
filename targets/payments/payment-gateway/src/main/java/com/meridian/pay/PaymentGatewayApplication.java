package com.meridian.pay;

import com.meridian.pay.config.CryptoProperties;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Not a real payment gateway -- a harness fixture (harness §5.1/§14.3).
 *
 * The CommandLineRunner below exists purely for Lock §6 CFG-R1: "Run
 * payment-gateway states B, C, D (with profile), F, H; read the actual
 * bound value at runtime" -- it logs the actually-bound
 * pay.keywrap.transformation value and exits. No HTTP server is started
 * (no spring-boot-starter-web dependency); CFG-R1 only needs the property
 * binding outcome, not a running TLS endpoint.
 */
@SpringBootApplication
@EnableConfigurationProperties(CryptoProperties.class)
public class PaymentGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(PaymentGatewayApplication.class, args).close();
    }

    @Bean
    public CommandLineRunner logBoundTransformation(CryptoProperties props) {
        return args -> System.out.println("CFG-R1 pay.keywrap.transformation=" + props.getTransformation());
    }
}
