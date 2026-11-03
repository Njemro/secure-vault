package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotNull;
import unibl.sni.securevault.entity.UserStatus;

public record UpdateUserStatusRequest(
        @NotNull UserStatus status
) {
}