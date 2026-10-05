package dev.joonselim.passport.crypto;

/** Thrown when an encrypted request cannot be decrypted. Returns HTTP 400. */
public class SealedPayloadException extends RuntimeException {

	public SealedPayloadException(String message) {
		super(message);
	}
}
