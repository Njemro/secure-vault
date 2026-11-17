
package unibl.sni.securevault.repository;

import unibl.sni.securevault.entity.HoneypotDemoState;
import org.springframework.data.jpa.repository.JpaRepository;

public interface HoneypotDemoStateRepository
        extends JpaRepository<HoneypotDemoState, Integer> {
}
