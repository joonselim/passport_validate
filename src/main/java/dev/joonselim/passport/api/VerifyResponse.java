package dev.joonselim.passport.api;

import java.util.List;
import java.util.Map;

import dev.joonselim.passport.verify.CheckStatus.Integrity;
import dev.joonselim.passport.verify.CheckStatus.Overall;
import dev.joonselim.passport.verify.CheckStatus.Signature;
import dev.joonselim.passport.verify.CheckStatus.Trust;

/** JSON returned by /verify: overall result, the three checks, and extra details. */
public record VerifyResponse(Overall overall, Checks checks, Details details, List<String> errors) {

	public record Checks(DataIntegrity dataIntegrity, SignatureCheck signature, IssuerTrust issuerTrust) {
	}

	public record DataIntegrity(Integrity status, String digestAlgorithm, Map<String, Integrity> dataGroups) {
	}

	public record SignatureCheck(Signature status, String algorithm) {
	}

	public record IssuerTrust(Trust status, String reason) {
	}

	public record Details(Mrz mrz, DocumentSigner documentSigner, Sod sod) {
	}

	public record Mrz(String documentCode, String documentNumber, String lastName, String firstName,
			String nationality, String dateOfBirth, String dateOfExpiry, String gender, String issuingState) {
	}

	public record DocumentSigner(String subject, String issuer, String serial, String notBefore, String notAfter,
			boolean withinValidity, String signatureAlgorithm) {
	}

	public record Sod(String ldsVersion, List<Integer> hashedDataGroups) {
	}
}
