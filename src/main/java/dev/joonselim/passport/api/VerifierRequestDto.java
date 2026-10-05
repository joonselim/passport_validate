package dev.joonselim.passport.api;

import java.util.List;

/** What a verifier asks for: a one-time nonce and the field names it wants. */
public record VerifierRequestDto(String nonce, String docType, List<String> elements, String verifier, String purpose) {
}
