package gateway;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

// Flat top-level package layout: this entry point lives in package 'gateway',
// while all configuration beans live in the sibling package 'config'.
// Spring Boot scans only downward from this class, so both roots must be
// declared explicitly - otherwise the beans in 'config' would not be registered.
@SpringBootApplication(scanBasePackages = { "gateway", "config" })
public class SecureVaultGatewayApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecureVaultGatewayApplication.class, args);
    }
}
