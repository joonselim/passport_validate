package dev.joonselim.passport.digitalid;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import dev.joonselim.passport.api.CredentialDto;
import dev.joonselim.passport.api.IssueRequest;
import dev.joonselim.passport.api.IssueResponse;
import dev.joonselim.passport.api.PresentRequest;
import dev.joonselim.passport.api.PresentResult;
import dev.joonselim.passport.api.VerifierRequestDto;
import dev.joonselim.passport.fixture.SyntheticPassport;
import dev.joonselim.passport.trust.CscaTrustStore;
import dev.joonselim.passport.verify.IntegrityChecker;
import dev.joonselim.passport.verify.IssuerTrustVerifier;
import dev.joonselim.passport.verify.PassiveAuthenticationService;
import dev.joonselim.passport.verify.SignatureVerifier;
import dev.joonselim.passport.verify.SodParser;

/** Issue a Digital ID from a fake passport, then present it to the verifier. The test plays the iPhone. */
class DigitalIdTest {

	static SyntheticPassport passport;
	static IssuerKeys issuerKeys;

	@BeforeAll
	static void fixture() throws Exception {
		passport = SyntheticPassport.create();
		issuerKeys = IssuerKeys.inMemory();
	}

	private static String b64(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	/** New P-256 key, standing in for the iPhone's Secure Enclave key. */
	private static KeyPair deviceKey() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		return kpg.generateKeyPair();
	}

	private static IssuanceService issuance(boolean trustCsca) {
		CscaTrustStore store = new CscaTrustStore(trustCsca ? List.of(passport.cscaCert) : List.of());
		var pa = new PassiveAuthenticationService(new SodParser(), new IntegrityChecker(), new SignatureVerifier(),
				new IssuerTrustVerifier(store));
		return new IssuanceService(pa, new DigitalIdIssuer(issuerKeys));
	}

	/** Does what the app does: get a challenge, sign it, send the passport and the device public key. */
	private static IssueResponse addPassport(IssuanceService service, KeyPair device) {
		byte[] challenge = service.newChallenge();
		byte[] proof = EcKeys.sign(device.getPrivate(), IssuanceService.proofInput(challenge, passport.sod));
		return service.issue(new IssueRequest(b64(passport.dg1), b64(passport.sod), b64(passport.dg2),
				b64(EcKeys.toX963((ECPublicKey) device.getPublic())), b64(challenge), b64(proof)));
	}

	/** Does what the app does when presenting: pick the requested fields and sign the nonce with the device key. */
	private static PresentRequest present(VerifierRequestDto req, CredentialDto id, List<String> send, KeyPair signer) {
		List<CredentialDto.ItemDto> items = id.items().stream().filter(i -> send.contains(i.elementIdentifier())).toList();
		byte[] nonce = Base64.getDecoder().decode(req.nonce());
		byte[] toSign = VerifierService.deviceAuthentication(nonce, id.docType(),
				items.stream().map(CredentialDto.ItemDto::elementIdentifier).toList());
		return new PresentRequest(req.nonce(), id.docType(), id.issuerAuth(), items, b64(EcKeys.sign(signer.getPrivate(), toSign)));
	}

	@Test
	void trustedPassport_getsAnId_withAllFields() throws Exception {
		IssueResponse r = addPassport(issuance(true), deviceKey());

		assertThat(r.credential()).isNotNull();
		assertThat(r.credential().docType()).isEqualTo(DigitalIdIssuer.DOC_TYPE);
		assertThat(r.credential().items()).extracting(CredentialDto.ItemDto::elementIdentifier)
				.contains("family_name", "given_name", "birth_date", "expiry_date", "document_number", "age_over_21");
	}

	@Test
	void untrustedPassport_getsNoId() throws Exception {
		IssueResponse r = addPassport(issuance(false), deviceKey());

		assertThat(r.credential()).isNull();
		assertThat(r.reason()).contains("UNVERIFIED");
	}

	@Test
	void wrongProof_isRefused() throws Exception {
		IssuanceService service = issuance(true);
		KeyPair device = deviceKey();
		KeyPair other = deviceKey();
		byte[] challenge = service.newChallenge();
		byte[] proof = EcKeys.sign(other.getPrivate(), IssuanceService.proofInput(challenge, passport.sod));

		assertThatThrownBy(() -> service.issue(new IssueRequest(b64(passport.dg1), b64(passport.sod), b64(passport.dg2),
				b64(EcKeys.toX963((ECPublicKey) device.getPublic())), b64(challenge), b64(proof))))
				.isInstanceOf(DigitalIdException.class).hasMessageContaining("signature");
	}

	@Test
	void challenge_worksOnlyOnce() throws Exception {
		IssuanceService service = issuance(true);
		KeyPair device = deviceKey();
		byte[] challenge = service.newChallenge();
		byte[] proof = EcKeys.sign(device.getPrivate(), IssuanceService.proofInput(challenge, passport.sod));
		IssueRequest request = new IssueRequest(b64(passport.dg1), b64(passport.sod), b64(passport.dg2),
				b64(EcKeys.toX963((ECPublicKey) device.getPublic())), b64(challenge), b64(proof));

		service.issue(request);
		assertThatThrownBy(() -> service.issue(request)).isInstanceOf(DigitalIdException.class);
	}

	@Test
	void ageCheck_isAccepted_andOnlyAgeIsDisclosed() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.age);

		PresentResult result = verifier.present(present(req, id, req.elements(), device));

		assertThat(result.result()).isEqualTo("ACCEPTED");
		assertThat(result.disclosed()).containsOnlyKeys("age_over_21").containsEntry("age_over_21", true);
	}

	@Test
	void identityCheck_disclosesNameAndDates() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.identity);

		PresentResult result = verifier.present(present(req, id, req.elements(), device));

		assertThat(result.result()).isEqualTo("ACCEPTED");
		assertThat(result.disclosed()).containsEntry("family_name", "HONG").containsEntry("given_name", "GILDONG")
				.containsEntry("birth_date", "1990-01-01").containsEntry("document_number", "M12345678");
	}

	@Test
	void sendingMoreThanRequested_isRejected() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.age);

		PresentResult result = verifier.present(present(req, id, List.of("age_over_21", "family_name"), device));

		assertThat(result.result()).isEqualTo("REJECTED");
		assertThat(result.checks()).containsEntry("requestedOnly", "NO");
		assertThat(result.disclosed()).isEmpty();
	}

	@Test
	void anotherDevice_cannotPresentTheId() throws Exception {
		CredentialDto id = addPassport(issuance(true), deviceKey()).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.age);

		PresentResult result = verifier.present(present(req, id, req.elements(), deviceKey()));

		assertThat(result.result()).isEqualTo("REJECTED");
		assertThat(result.checks()).containsEntry("deviceSignature", "INVALID");
	}

	@Test
	void changedField_isRejected() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.age);
		PresentRequest honest = present(req, id, req.elements(), device);
		byte[] itemBytes = Base64.getDecoder().decode(honest.items().get(0).bytes());
		itemBytes[itemBytes.length - 1] ^= 0x01;
		var forged = new CredentialDto.ItemDto(honest.items().get(0).namespace(), "age_over_21", b64(itemBytes));

		PresentResult result = verifier.present(new PresentRequest(honest.nonce(), honest.docType(), honest.issuerAuth(),
				List.of(forged), honest.deviceSignature()));

		assertThat(result.result()).isEqualTo("REJECTED");
		assertThat(result.checks()).containsEntry("dataDigests", "MISMATCH");
	}

	@Test
	void replayedPresentation_isRejected() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService verifier = new VerifierService(issuerKeys);
		VerifierRequestDto req = verifier.request(VerifierService.Purpose.age);
		PresentRequest presentation = present(req, id, req.elements(), device);

		verifier.present(presentation);
		PresentResult again = verifier.present(presentation);

		assertThat(again.result()).isEqualTo("REJECTED");
		assertThat(again.checks()).containsEntry("nonce", "UNKNOWN");
	}

	@Test
	void idFromAnotherIssuer_isRejected() throws Exception {
		KeyPair device = deviceKey();
		CredentialDto id = addPassport(issuance(true), device).credential();
		VerifierService otherVerifier = new VerifierService(IssuerKeys.inMemory());
		VerifierRequestDto req = otherVerifier.request(VerifierService.Purpose.age);

		PresentResult result = otherVerifier.present(present(req, id, req.elements(), device));

		assertThat(result.result()).isEqualTo("REJECTED");
		assertThat(result.checks()).containsEntry("issuerSignature", "INVALID");
	}
}
