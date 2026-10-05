package dev.joonselim.passport.api;

import java.util.Base64;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import dev.joonselim.passport.crypto.HpkeChannel;
import dev.joonselim.passport.verify.PassiveAuthenticationService;
import dev.joonselim.passport.verify.PassportFiles;
import dev.joonselim.passport.verify.PassportParseException;
import dev.joonselim.passport.trust.CscaTrustStore;
import jakarta.validation.Valid;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** HTTP endpoints the iOS app calls. */
@RestController
@RequestMapping(path = "/api/v1/passport", produces = MediaType.APPLICATION_JSON_VALUE)
public class VerifyController {

	private final PassiveAuthenticationService service;
	private final CscaTrustStore trustStore;
	private final HpkeChannel channel;
	private final JsonMapper json;

	public VerifyController(PassiveAuthenticationService service, CscaTrustStore trustStore, HpkeChannel channel,
			JsonMapper json) {
		this.service = service;
		this.trustStore = trustStore;
		this.channel = channel;
		this.json = json;
	}

	/** GET /health: is the server up, how many CSCA certificates are loaded, and which encryption key it uses. */
	@GetMapping("/health")
	public Map<String, Object> health() {
		return Map.of(
				"status", "ok",
				"cscaCertificates", trustStore.certificates().size(),
				"hpkeKeyId", channel.keyId(),
				"hpkePublicKey", Base64.getEncoder().encodeToString(channel.publicKey()));
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

	/** POST /verify-sealed: same as /verify, but the request and the answer are encrypted (HPKE). */
	@PostMapping(path = "/verify-sealed", consumes = MediaType.APPLICATION_JSON_VALUE)
	public SealedResponse verifySealed(@Valid @RequestBody SealedRequest request) {
		HpkeChannel.Opened opened = channel.open(decode(request.enc(), "enc"), decode(request.ciphertext(), "ciphertext"));
		VerifyRequest inner;
		try {
			inner = json.readValue(opened.plaintext(), VerifyRequest.class);
		}
		catch (JacksonException e) {
			throw new PassportParseException("decrypted payload is not valid JSON");
		}
		if (inner.dg1() == null || inner.dg1().isBlank() || inner.sod() == null || inner.sod().isBlank()) {
			throw new PassportParseException("dg1 and sod are required");
		}
		byte[] answer = json.writeValueAsBytes(verify(inner));
		return new SealedResponse(Base64.getEncoder().encodeToString(HpkeChannel.sealResponse(opened.responseKey(), answer)));
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
