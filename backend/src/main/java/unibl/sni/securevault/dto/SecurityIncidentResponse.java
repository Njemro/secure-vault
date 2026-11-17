
package unibl.sni.securevault.dto;

import java.time.LocalDateTime;

public record SecurityIncidentResponse(
        String id,
        LocalDateTime eventTime,
        String eventType,
        String username,
        String sourceIp,
        String metadata
) {
}
