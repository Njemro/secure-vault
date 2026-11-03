package unibl.sni.securevault.dto;

import jakarta.validation.constraints.NotNull;
import unibl.sni.securevault.entity.Role;

public record UpdateUserRoleRequest(
        @NotNull Role role
) {
}