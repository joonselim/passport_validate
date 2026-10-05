package dev.joonselim.passport.api;

/** Issuance answer: the passport check result, and the Digital ID if it passed (otherwise null with a reason). */
public record IssueResponse(VerifyResponse verification, CredentialDto credential, String reason) {
}
