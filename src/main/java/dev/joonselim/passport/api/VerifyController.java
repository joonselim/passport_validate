package dev.joonselim.passport.api;

import java.util.Base64;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.joonselim.passport.verify.PassiveAuthenticationService;
import dev.joonselim.passport.verify.PassportFiles;
import dev.joonselim.passport.verify.PassportParseException;
import dev.joonselim.passport.trust.CscaTrustStore;
import jakarta.validation.Valid;

/** HTTP endpoints the iOS app calls. */
@RestController
@RequestMapping(path = "/api/v1/passport", produces = MediaType.APPLICATION_JSON_VALUE)
public class VerifyController {

	private final PassiveAuthenticationService service;
	private final CscaTrustStore trustStore;

	public VerifyController(PassiveAuthenticationService service, CscaTrustStore trustStore) {
		this.service = service;
		this.trustStore = trustStore;
	}

	/** GET /health: is the server up, and how many CSCA certificates are loaded. */
	@GetMapping("/health")
	public Map<String, Object> health() {
		return Map.of("status", "ok", "cscaCertificates", trustStore.certificates().size());
	}

	/** POST /verify: decode the Base64 files and run all checks. */
	@PostMapping(path = "/verify", consumes = MediaType.APPLICATION_JSON_VALUE)
	public VerifyResponse verify(@Valid @RequestBody VerifyRequest request) {
		PassportFiles files = new PassportFiles(
				decode(request.dg1(), "dg1"),
				decode(request.sod(), "sod"),
				request.dg2() == null || request.dg2().isBlank() ? null : decode(request.dg2(), "dg2"));
		return service.verify(files);
	}

	/** Base64 text to bytes. */
	private static byte[] decode(String b64, String field) {
		try {
			return Base64.getDecoder().decode(b64.strip());
		}
		catch (IllegalArgumentException e) {
			throw new PassportParseException(field + ": invalid Base64");
		}
	}
}
