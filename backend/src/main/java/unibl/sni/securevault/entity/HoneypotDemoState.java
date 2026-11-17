
package unibl.sni.securevault.entity;

import jakarta.persistence.*;
import java.time.LocalDateTime;
import unibl.sni.securevault.entity.User;

@Entity
@Table(name = "honeypot_demo_state")
public class HoneypotDemoState {

    @Id
    @Column(name = "id", nullable = false)
    private Integer id;

    @Column(name = "enabled_until")
    private LocalDateTime enabledUntil;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "enabled_by")
    private User enabledBy;

    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    protected HoneypotDemoState() {
    }

    public boolean isEnabled() {
        return enabledUntil != null
                && enabledUntil.isAfter(LocalDateTime.now());
    }

    public void enable(User admin, int durationMinutes) {
        this.enabledBy = admin;
        this.enabledUntil = LocalDateTime.now().plusMinutes(durationMinutes);
        this.updatedAt = LocalDateTime.now();
    }

    public void disable() {
        this.enabledUntil = null;
        this.enabledBy = null;
        this.updatedAt = LocalDateTime.now();
    }

    public LocalDateTime getEnabledUntil() {
        return enabledUntil;
    }

    public User getEnabledBy() {
        return enabledBy;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }
}
