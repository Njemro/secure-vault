
package unibl.sni.securevault.dto;

import java.time.LocalDateTime;

public record HoneypotDemoStatusResponse(
        boolean enabled,
        LocalDateTime enabledUntil,
        String enabledBy
) {
}
