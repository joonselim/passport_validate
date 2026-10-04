package dev.joonselim.passport.verify;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.joonselim.passport.api.VerifyResponse;
import dev.joonselim.passport.fixture.SyntheticPassport;
import dev.joonselim.passport.trust.CscaTrustStore;
import dev.joonselim.passport.verify.CheckStatus.Integrity;
import dev.joonselim.passport.verify.CheckStatus.Overall;
import dev.joonselim.passport.verify.CheckStatus.Signature;
import dev.joonselim.passport.verify.CheckStatus.Trust;

/** All checks, run on a fake passport. */
class PassiveAuthenticationServiceTest {

	static SyntheticPassport passport;

	@BeforeAll
	static void fixture() throws Exception {
		passport = SyntheticPassport.create();
	}

	private static PassiveAuthenticationService service(CscaTrustStore store) {
		return new PassiveAuthenticationService(new SodParser(), new IntegrityChecker(), new SignatureVerifier(),
				new IssuerTrustVerifier(store));
	}

	@Test
	void genuinePassportWithTrustedCsca_passes() {
		VerifyResponse r = service(new CscaTrustStore(List.of(passport.cscaCert)))
				.verify(new PassportFiles(passport.dg1, passport.sod, passport.dg2));

		assertThat(r.overall()).isEqualTo(Overall.PASS);
		assertThat(r.checks().dataIntegrity().status()).isEqualTo(Integrity.MATCH);
		assertThat(r.checks().dataIntegrity().dataGroups()).containsEntry("DG1", Integrity.MATCH)
				.containsEntry("DG2", Integrity.MATCH);
		assertThat(r.checks().signature().status()).isEqualTo(Signature.VALID);
		assertThat(r.checks().issuerTrust().status()).isEqualTo(Trust.TRUSTED);
		assertThat(r.errors()).isEmpty();
		assertThat(r.details().mrz().documentNumber()).isEqualTo("M12345678");
		assertThat(r.details().mrz().lastName()).isEqualTo("HONG");
		assertThat(r.details().documentSigner().withinValidity()).isTrue();
		assertThat(r.details().sod().hashedDataGroups()).containsExactly(1, 2);
	}

	@Test
	void genuinePassportWithoutCsca_isUnverified() {
		VerifyResponse r = service(new CscaTrustStore(List.of()))
				.verify(new PassportFiles(passport.dg1, passport.sod, passport.dg2));

		assertThat(r.overall()).isEqualTo(Overall.UNVERIFIED);
		assertThat(r.checks().dataIntegrity().status()).isEqualTo(Integrity.MATCH);
		assertThat(r.checks().signature().status()).isEqualTo(Signature.VALID);
		assertThat(r.checks().issuerTrust().status()).isEqualTo(Trust.UNVERIFIED);
	}

	@Test
	void dg1Only_dg2ReportedNotProvided() {
		VerifyResponse r = service(new CscaTrustStore(List.of(passport.cscaCert)))
				.verify(new PassportFiles(passport.dg1, passport.sod, null));

		assertThat(r.overall()).isEqualTo(Overall.PASS);
		assertThat(r.checks().dataIntegrity().dataGroups()).containsEntry("DG2", Integrity.NOT_PROVIDED);
	}

	@Test
	void tamperedDg1_failsIntegrity_signatureStillValid() {
		VerifyResponse r = service(new CscaTrustStore(List.of(passport.cscaCert)))
				.verify(new PassportFiles(SyntheticPassport.tamper(passport.dg1), passport.sod, passport.dg2));

		assertThat(r.overall()).isEqualTo(Overall.FAIL);
		assertThat(r.checks().dataIntegrity().status()).isEqualTo(Integrity.MISMATCH);
		assertThat(r.checks().dataIntegrity().dataGroups()).containsEntry("DG1", Integrity.MISMATCH)
				.containsEntry("DG2", Integrity.MATCH);
		assertThat(r.checks().signature().status()).isEqualTo(Signature.VALID);
		assertThat(r.errors()).anyMatch(e -> e.startsWith("integrity DG1"));
	}

	@Test
	void tamperedDg2_failsIntegrity() {
		VerifyResponse r = service(new CscaTrustStore(List.of(passport.cscaCert)))
				.verify(new PassportFiles(passport.dg1, passport.sod, SyntheticPassport.tamper(passport.dg2)));

		assertThat(r.overall()).isEqualTo(Overall.FAIL);
		assertThat(r.checks().dataIntegrity().dataGroups()).containsEntry("DG2", Integrity.MISMATCH);
	}

	@Test
	void tamperedSodSignature_isInvalid() {
		// The last byte of the SOD is part of the signature
		VerifyResponse r = service(new CscaTrustStore(List.of(passport.cscaCert)))
				.verify(new PassportFiles(passport.dg1, SyntheticPassport.tamper(passport.sod), passport.dg2));

		assertThat(r.overall()).isEqualTo(Overall.FAIL);
		assertThat(r.checks().dataIntegrity().status()).isEqualTo(Integrity.MATCH);
		assertThat(r.checks().signature().status()).isEqualTo(Signature.INVALID);
	}

	@Test
	void unknownCsca_failsTrust() throws Exception {
		SyntheticPassport other = SyntheticPassport.create("XXA", "Other CSCA");
		VerifyResponse r = service(new CscaTrustStore(List.of(other.cscaCert)))
				.verify(new PassportFiles(passport.dg1, passport.sod, passport.dg2));

		assertThat(r.overall()).isEqualTo(Overall.FAIL);
		assertThat(r.checks().signature().status()).isEqualTo(Signature.VALID);
		assertThat(r.checks().issuerTrust().status()).isEqualTo(Trust.FAILED);
	}

	@Test
	void wrongTag_isParseError() {
		assertThatThrownBy(() -> service(new CscaTrustStore(List.of()))
				.verify(new PassportFiles(passport.dg2, passport.sod, null)))
				.isInstanceOf(PassportParseException.class)
				.hasMessageContaining("EF.DG1");
		assertThatThrownBy(() -> service(new CscaTrustStore(List.of()))
				.verify(new PassportFiles(passport.dg1, passport.dg1, null)))
				.isInstanceOf(PassportParseException.class)
				.hasMessageContaining("EF.SOD");
	}
}
