/**
 * JPA entities. Columns may only hold ciphertext, IVs, wrapped keys, public
 * keys, salts and metadata - never plaintext secrets, master passwords,
 * KEKs, plaintext DEKs or unencrypted private keys.
 */
package unibl.sni.securevault.entity;
