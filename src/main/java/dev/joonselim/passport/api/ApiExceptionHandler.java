package dev.joonselim.passport.api;

import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import dev.joonselim.passport.crypto.SealedPayloadException;
import dev.joonselim.passport.verify.PassportParseException;

/** Turns errors into JSON error responses. */
@RestControllerAdvice
public class ApiExceptionHandler {

	/** 422: the data is not a valid passport file. */
	@ExceptionHandler(PassportParseException.class)
	public ResponseEntity<Map<String, Object>> unparseable(PassportParseException e) {
		return ResponseEntity.status(HttpStatus.UNPROCESSABLE_CONTENT)
				.body(Map.of("error", "unparseable_input", "errors", List.of(e.getMessage())));
	}

	/** 400: the encrypted request could not be decrypted. */
	@ExceptionHandler(SealedPayloadException.class)
	public ResponseEntity<Map<String, Object>> undecryptable(SealedPayloadException e) {
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(Map.of("error", "undecryptable", "errors", List.of(e.getMessage())));
	}

	/** 400: a required field (dg1 or sod) is missing. */
	@ExceptionHandler(MethodArgumentNotValidException.class)
	public ResponseEntity<Map<String, Object>> invalid(MethodArgumentNotValidException e) {
		List<String> messages = e.getBindingResult().getFieldErrors().stream()
				.map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
				.toList();
		return ResponseEntity.status(HttpStatus.BAD_REQUEST)
				.body(Map.of("error", "invalid_request", "errors", messages));
	}
}
