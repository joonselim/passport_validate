package dev.joonselim.passport.verify;

/** Thrown when the input is not a passport file. Returns HTTP 422. */
public class PassportParseException extends RuntimeException {

	public PassportParseException(String message) {
		super(message);
	}

	public PassportParseException(String message, Throwable cause) {
		super(message, cause);
	}
}
