package unibl.sni.securevault.entity;

/**
 * Account status. SUSPENDED covers the "frozen" state used after honeypot
 * access or suspicious activity (AGENTS.md section 13).
 */
public enum UserStatus {
    ACTIVE,
    SUSPENDED,
    DISABLED
}
