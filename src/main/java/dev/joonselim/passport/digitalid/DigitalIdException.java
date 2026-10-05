package dev.joonselim.passport.digitalid;

/** Thrown when an issuance or presentation request is not acceptable. Returns HTTP 400. */
public class DigitalIdException extends RuntimeException {

	private final String code;

	public DigitalIdException(String code, String message) {
		super(message);
		this.code = code;
	}

	/** Short error code for the JSON response, e.g. "invalid_challenge". */
	public String code() {
		return code;
	}
}
