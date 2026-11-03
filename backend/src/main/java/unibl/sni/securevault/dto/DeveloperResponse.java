package unibl.sni.securevault.dto;

import java.util.UUID;

public record DeveloperResponse(
        UUID id,
        String username
) {
}