package dev.joonselim.passport.api;

import java.util.Base64;
import java.util.Map;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import dev.joonselim.passport.digitalid.DigitalIdException;
import dev.joonselim.passport.digitalid.IssuanceService;
import dev.joonselim.passport.digitalid.VerifierService;
import jakarta.validation.Valid;

/** Digital ID endpoints: issuing an ID (issuer) and checking a presented ID (demo verifier). */
@RestController
@RequestMapping(path = "/api/v1", produces = MediaType.APPLICATION_JSON_VALUE)
public class DigitalIdController {

	private final IssuanceService issuance;
	private final VerifierService verifier;
	private final SealedJson sealed;

	public DigitalIdController(IssuanceService issuance, VerifierService verifier, SealedJson sealed) {
		this.issuance = issuance;
		this.verifier = verifier;
		this.sealed = sealed;
	}

	/** GET /issuer/challenge: a one-time value the app signs with its device key. */
	@GetMapping("/issuer/challenge")
	public Map<String, Object> challenge() {
		return Map.of(
				"challenge", Base64.getEncoder().encodeToString(issuance.newChallenge()),
				"expiresInSeconds", issuance.challengeLifetime().toSeconds());
	}

	/** POST /issuer/issue-sealed: check the passport and, if it passes, issue a Digital ID (encrypted both ways). */
	@PostMapping(path = "/issuer/issue-sealed", consumes = MediaType.APPLICATION_JSON_VALUE)
	public SealedResponse issue(@Valid @RequestBody SealedRequest request) {
		SealedJson.Opened<IssueRequest> opened = sealed.open(request, IssueRequest.class);
		return sealed.seal(opened, issuance.issue(opened.value()));
	}

	/** GET /verifier/request?purpose=age|identity: what the demo verifier wants to see. */
	@GetMapping("/verifier/request")
	public VerifierRequestDto request(@RequestParam(defaultValue = "age") String purpose) {
		try {
			return verifier.request(VerifierService.Purpose.valueOf(purpose));
		}
		catch (IllegalArgumentException e) {
			throw new DigitalIdException("unknown_purpose", "purpose must be age or identity");
		}
	}

	/** POST /verifier/present-sealed: the verifier checks a presented ID (encrypted both ways). */
	@PostMapping(path = "/verifier/present-sealed", consumes = MediaType.APPLICATION_JSON_VALUE)
	public SealedResponse present(@Valid @RequestBody SealedRequest request) {
		SealedJson.Opened<PresentRequest> opened = sealed.open(request, PresentRequest.class);
		return sealed.seal(opened, verifier.present(opened.value()));
	}
}
