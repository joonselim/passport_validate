package dev.joonselim.passport.digitalid;

import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.LocalDate;

import org.springframework.stereotype.Service;

import com.upokecenter.cbor.CBORObject;

import dev.joonselim.passport.api.ApiBase64;
import dev.joonselim.passport.api.CredentialDto;
import dev.joonselim.passport.api.IssueRequest;
import dev.joonselim.passport.api.IssueResponse;
import dev.joonselim.passport.api.VerifyResponse;
import dev.joonselim.passport.verify.CheckStatus.Overall;
import dev.joonselim.passport.verify.PassiveAuthenticationService;
import dev.joonselim.passport.verify.PassportFiles;

/**
 * Issues a Digital ID: checks the challenge and the device key proof, runs Passive Authentication,
 * and only if the passport passes, signs a new ID bound to the device key. Nothing is stored.
 */
@Service
public class IssuanceService {

	private final PassiveAuthenticationService passiveAuthentication;
	private final DigitalIdIssuer issuer;
	private final NonceStore<Boolean> challenges = new NonceStore<>(Duration.ofMinutes(2));

	public IssuanceService(PassiveAuthenticationService passiveAuthentication, DigitalIdIssuer issuer) {
		this.passiveAuthentication = passiveAuthentication;
		this.issuer = issuer;
	}

	/** A new one-time challenge. The app signs it with its device key. */
	public byte[] newChallenge() {
		return challenges.create(Boolean.TRUE);
	}

	/** How long a challenge is valid. */
	public Duration challengeLifetime() {
		return challenges.lifetime();
	}

	/** Checks everything and returns the verification result, plus the ID if the passport passed. */
	public IssueResponse issue(IssueRequest request) {
		byte[] challenge = ApiBase64.decode(request.challenge(), "challenge");
		if (challenges.consume(challenge).isEmpty()) {
			throw new DigitalIdException("invalid_challenge", "challenge is unknown, used, or expired");
		}
		PassportFiles files = new PassportFiles(
				ApiBase64.decode(request.dg1(), "dg1"),
				ApiBase64.decode(request.sod(), "sod"),
				request.dg2() == null || request.dg2().isBlank() ? null : ApiBase64.decode(request.dg2(), "dg2"));
		ECPublicKey deviceKey = EcKeys.fromX963(ApiBase64.decode(request.devicePublicKey(), "devicePublicKey"));
		byte[] proof = ApiBase64.decode(request.proof(), "proof");
		if (!EcKeys.verify(deviceKey, proofInput(challenge, files.sod()), proof)) {
			throw new DigitalIdException("bad_proof", "device key signature over the challenge is not valid");
		}

		VerifyResponse verification = passiveAuthentication.verify(files);
		if (verification.overall() != Overall.PASS) {
			return new IssueResponse(verification, null, "passport check result is " + verification.overall());
		}
		if (issuer.expiryDate(files.dg1()).isBefore(LocalDate.now())) {
			return new IssueResponse(verification, null, "passport is expired");
		}
		return new IssueResponse(verification, CredentialDto.of(issuer.issue(files.dg1(), files.dg2(), deviceKey)), null);
	}

	/** What the device signs to prove it holds the key: CBOR ["IssuanceRequest", challenge, SHA-256(SOD)]. */
	public static byte[] proofInput(byte[] challenge, byte[] sod) {
		return CBORObject.NewArray().Add("IssuanceRequest").Add(challenge).Add(DigitalIdIssuer.sha256(sod)).EncodeToBytes();
	}
}
