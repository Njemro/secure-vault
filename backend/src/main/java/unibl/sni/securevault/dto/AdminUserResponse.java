package unibl.sni.securevault.dto;

import unibl.sni.securevault.entity.Role;
import unibl.sni.securevault.entity.User;
import unibl.sni.securevault.entity.UserStatus;

import java.time.LocalDateTime;
import java.util.UUID;

public record AdminUserResponse(
        UUID id,
        String username,
        Role role,
        UserStatus status,
        LocalDateTime createdAt
) {
    public static AdminUserResponse from(User user) {
        return new AdminUserResponse(
                user.getId(),
                user.getUsername(),
                user.getRole(),
                user.getStatus(),
                user.getCreatedAt()
        );
    }
}
