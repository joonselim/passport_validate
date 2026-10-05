package dev.joonselim.passport.api;

import jakarta.validation.constraints.NotBlank;

/** Encrypted request body: the HPKE encapsulated key and the encrypted VerifyRequest JSON, both Base64. */
public record SealedRequest(
		@NotBlank(message = "enc is required") String enc,
		@NotBlank(message = "ciphertext is required") String ciphertext) {
}
