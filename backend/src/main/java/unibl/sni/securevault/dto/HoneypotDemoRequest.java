
package unibl.sni.securevault.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;

public record HoneypotDemoRequest(
        @Min(1)
        @Max(30)
        int durationMinutes
) {
}
