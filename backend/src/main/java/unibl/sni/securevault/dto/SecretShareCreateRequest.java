package unibl.sni.securevault.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;

import java.util.List;

/**
 * Request to share one secret with several individual recipients (no team
 * concept). Each entry pairs a recipient id with the DEK already encrypted
 * for that recipient by the sharing client (RSA-OAEP with the recipient's
 * public key) - the server performs no cryptographic wrapping.
 *
 * <p>The secret id belongs in the future endpoint path and the sharing
 * owner's id comes from the authenticated security context, not from this
 * body. Do not log instances of this record: entries carry encrypted DEKs.
 */
public record SecretShareCreateRequest(
        @NotEmpty @Valid List<RecipientShareInput> recipients) {
}
