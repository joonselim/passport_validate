package dev.joonselim.passport.api;

import java.util.Base64;

import dev.joonselim.passport.verify.PassportParseException;

/** Base64 decoding for request fields, with a clear error naming the field. */
public final class ApiBase64 {

	private ApiBase64() {
	}

	/** Base64 text to bytes. Missing or broken input returns HTTP 422. */
	public static byte[] decode(String b64, String field) {
		if (b64 == null || b64.isBlank()) {
			throw new PassportParseException(field + " is required");
		}
		try {
			return Base64.getDecoder().decode(b64.strip());
		}
		catch (IllegalArgumentException e) {
			throw new PassportParseException(field + ": invalid Base64");
		}
	}
}
