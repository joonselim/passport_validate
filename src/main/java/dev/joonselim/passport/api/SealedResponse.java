package dev.joonselim.passport.api;

/** Encrypted answer: the VerifyResponse JSON sealed with the response key, Base64. */
public record SealedResponse(String ciphertext) {
}
