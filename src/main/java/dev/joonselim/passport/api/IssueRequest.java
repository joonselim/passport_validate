package dev.joonselim.passport.api;

/**
 * Issuance request (sent encrypted): the chip files, the device public key (65-byte uncompressed P-256),
 * the server's challenge, and the device's signature over it. All Base64.
 */
public record IssueRequest(String dg1, String sod, String dg2, String devicePublicKey, String challenge, String proof) {
}
