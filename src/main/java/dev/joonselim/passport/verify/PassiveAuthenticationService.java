package dev.joonselim.passport.verify;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.TreeSet;

import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;
import org.springframework.stereotype.Service;

import dev.joonselim.passport.api.VerifyResponse;
import dev.joonselim.passport.api.VerifyResponse.Checks;
import dev.joonselim.passport.api.VerifyResponse.DataIntegrity;
import dev.joonselim.passport.api.VerifyResponse.Details;
import dev.joonselim.passport.api.VerifyResponse.DocumentSigner;
import dev.joonselim.passport.api.VerifyResponse.IssuerTrust;
import dev.joonselim.passport.api.VerifyResponse.Mrz;
import dev.joonselim.passport.api.VerifyResponse.SignatureCheck;
import dev.joonselim.passport.api.VerifyResponse.Sod;
import dev.joonselim.passport.verify.CheckStatus.Integrity;
import dev.joonselim.passport.verify.CheckStatus.Overall;
import dev.joonselim.passport.verify.CheckStatus.Signature;
import dev.joonselim.passport.verify.CheckStatus.Trust;

/** Runs all checks and builds the response. */
@Service
public class PassiveAuthenticationService {

	private final SodParser sodParser;
	private final IntegrityChecker integrityChecker;
	private final SignatureVerifier signatureVerifier;
	private final IssuerTrustVerifier issuerTrustVerifier;

	public PassiveAuthenticationService(SodParser sodParser, IntegrityChecker integrityChecker,
			SignatureVerifier signatureVerifier, IssuerTrustVerifier issuerTrustVerifier) {
		this.sodParser = sodParser;
		this.integrityChecker = integrityChecker;
		this.signatureVerifier = signatureVerifier;
		this.issuerTrustVerifier = issuerTrustVerifier;
	}

	/** Parses the SOD, runs the three checks, and decides PASS / FAIL / UNVERIFIED. */
	public VerifyResponse verify(PassportFiles files) {
		List<String> errors = new ArrayList<>();

		Tlv.requireTag(files.dg1(), PassportFiles.DG1_TAG, "EF.DG1");
		if (files.dg2() != null) {
			Tlv.requireTag(files.dg2(), PassportFiles.DG2_TAG, "EF.DG2");
		}
		SodInfo sod = sodParser.parse(files.sod());

		IntegrityChecker.Result integrity = integrityChecker.check(sod, files);
		SignatureVerifier.Result signature = signatureVerifier.verify(sod);
		IssuerTrustVerifier.Result trust = issuerTrustVerifier.verify(sod);

		integrity.reasons().forEach((dg, why) -> errors.add("integrity " + dg + ": " + why));
		if (signature.status() == Signature.INVALID) {
			errors.add("signature: " + signature.reason());
		}
		if (trust.status() == Trust.FAILED) {
			errors.add("issuerTrust: " + trust.reason());
		}

		Overall overall;
		if (integrity.status() == Integrity.MISMATCH || signature.status() == Signature.INVALID
				|| trust.status() == Trust.FAILED) {
			overall = Overall.FAIL;
		}
		else if (trust.status() == Trust.UNVERIFIED) {
			overall = Overall.UNVERIFIED;
		}
		else {
			overall = Overall.PASS;
		}

		Checks checks = new Checks(
				new DataIntegrity(integrity.status(), integrity.digestAlgorithm(), integrity.dataGroups()),
				new SignatureCheck(signature.status(), signature.algorithm()),
				new IssuerTrust(trust.status(), trust.reason()));

		Details details = new Details(
				parseMrz(files.dg1(), errors),
				sod.documentSigner().map(PassiveAuthenticationService::describe).orElse(null),
				new Sod(sod.ldsVersion(), new TreeSet<>(sod.dataGroupHashes().keySet()).stream().toList()));

		return new VerifyResponse(overall, checks, details, errors);
	}

	/** Reads name, number and dates from DG1 (display only). */
	private static Mrz parseMrz(byte[] dg1, List<String> errors) {
		try {
			MRZInfo mrz = new DG1File(new ByteArrayInputStream(dg1)).getMRZInfo();
			String[] given = mrz.getSecondaryIdentifierComponents();
			return new Mrz(
					mrz.getDocumentCode(),
					mrz.getDocumentNumber(),
					mrz.getPrimaryIdentifier(),
					given == null ? "" : String.join(" ", given),
					mrz.getNationality(),
					mrz.getDateOfBirth(),
					mrz.getDateOfExpiry(),
					mrz.getGender() == null ? null : mrz.getGender().name(),
					mrz.getIssuingState());
		}
		catch (IOException | RuntimeException e) {
			errors.add("DG1 parse (display only): " + e.getMessage());
			return null;
		}
	}

	/** Summary of the signer certificate. */
	private static DocumentSigner describe(X509Certificate c) {
		Date now = new Date();
		boolean within = !now.before(c.getNotBefore()) && !now.after(c.getNotAfter());
		return new DocumentSigner(
				c.getSubjectX500Principal().getName(),
				c.getIssuerX500Principal().getName(),
				c.getSerialNumber().toString(16).toUpperCase(),
				c.getNotBefore().toInstant().atOffset(ZoneOffset.UTC).toString(),
				c.getNotAfter().toInstant().atOffset(ZoneOffset.UTC).toString(),
				within,
				c.getSigAlgName());
	}
}
