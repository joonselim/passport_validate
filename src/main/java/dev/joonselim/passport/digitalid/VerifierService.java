package dev.joonselim.passport.digitalid;

import java.security.MessageDigest;
import java.security.interfaces.ECPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.upokecenter.cbor.CBORObject;
import com.upokecenter.cbor.CBORType;

import dev.joonselim.passport.api.ApiBase64;
import dev.joonselim.passport.api.CredentialDto;
import dev.joonselim.passport.api.PresentRequest;
import dev.joonselim.passport.api.PresentResult;
import dev.joonselim.passport.api.VerifierRequestDto;

/**
 * A demo verifier (in real life, a different company): asks for some fields with a one-time nonce,
 * then checks what the iPhone sends back. It trusts only the Digital ID issuer certificate.
 */
@Service
public class VerifierService {

	/** What the verifier asks for. */
	public enum Purpose {
		age("Age check", List.of("age_over_21")),
		identity("Identity check", List.of("portrait", "family_name", "given_name", "birth_date", "document_number", "expiry_date"));

		final String label;
		final List<String> elements;

		Purpose(String label, List<String> elements) {
			this.label = label;
			this.elements = elements;
		}
	}

	private final IssuerKeys trustedIssuer;
	private final NonceStore<Purpose> requests = new NonceStore<>(Duration.ofMinutes(5));

	public VerifierService(IssuerKeys trustedIssuer) {
		this.trustedIssuer = trustedIssuer;
	}

	/** Starts a request: a fresh nonce and the list of fields wanted. */
	public VerifierRequestDto request(Purpose purpose) {
		byte[] nonce = requests.create(purpose);
		return new VerifierRequestDto(Base64.getEncoder().encodeToString(nonce), DigitalIdIssuer.DOC_TYPE,
				purpose.elements, "Demo verifier", purpose.label);
	}

	/** Checks a presentation: nonce, requested fields only, issuer signature, validity, field hashes, device signature. */
	public PresentResult present(PresentRequest request) {
		byte[] nonce = ApiBase64.decode(request.nonce(), "nonce");
		byte[] issuerAuth = ApiBase64.decode(request.issuerAuth(), "issuerAuth");
		byte[] deviceSignature = ApiBase64.decode(request.deviceSignature(), "deviceSignature");
		List<CredentialDto.ItemDto> items = request.items() == null ? List.of() : request.items();
		List<String> ids = items.stream().map(CredentialDto.ItemDto::elementIdentifier).toList();

		Map<String, String> checks = new LinkedHashMap<>();
		Optional<Purpose> purpose = requests.consume(nonce);
		checks.put("nonce", purpose.isPresent() ? "FRESH" : "UNKNOWN");
		boolean onlyRequested = purpose.isPresent() && !ids.isEmpty() && purpose.get().elements.containsAll(ids);
		checks.put("requestedOnly", onlyRequested ? "YES" : "NO");

		CBORObject mso = null;
		byte[] msoBytes = Cose.verify1(issuerAuth, trustedIssuer.certificate());
		checks.put("issuerSignature", msoBytes == null ? "INVALID" : "VALID");
		if (msoBytes != null) {
			mso = CBORObject.DecodeFromBytes(CBORObject.DecodeFromBytes(msoBytes).UntagOne().GetByteString());
		}

		checks.put("validity", mso == null ? "NOT_CHECKED" : validity(mso, request.docType()));
		checks.put("dataDigests", mso == null ? "NOT_CHECKED" : digests(mso, items));
		checks.put("deviceSignature", mso == null ? "NOT_CHECKED" : deviceSignature(mso, nonce, request.docType(), ids, deviceSignature));

		boolean accepted = checks.equals(Map.of(
				"nonce", "FRESH", "requestedOnly", "YES", "issuerSignature", "VALID",
				"validity", "VALID", "dataDigests", "MATCH", "deviceSignature", "VALID"));
		Map<String, Object> disclosed = new LinkedHashMap<>();
		if (accepted) {
			for (CredentialDto.ItemDto item : items) {
				disclosed.put(item.elementIdentifier(), displayValue(itemMap(item).get("elementValue")));
			}
		}
		return new PresentResult(accepted ? "ACCEPTED" : "REJECTED", checks,
				trustedIssuer.certificate().getSubjectX500Principal().getName(), disclosed);
	}

	/** What the device signs when presenting: CBOR ["DeviceAuthentication", nonce, docType, [field names]]. */
	public static byte[] deviceAuthentication(byte[] nonce, String docType, List<String> elementIds) {
		CBORObject names = CBORObject.NewArray();
		elementIds.forEach(names::Add);
		return CBORObject.NewArray().Add("DeviceAuthentication").Add(nonce).Add(docType).Add(names).EncodeToBytes();
	}

	/** Right document type, and now is inside validFrom..validUntil. */
	private static String validity(CBORObject mso, String docType) {
		try {
			if (!DigitalIdIssuer.DOC_TYPE.equals(mso.get("docType").AsString()) || !DigitalIdIssuer.DOC_TYPE.equals(docType)) {
				return "WRONG_DOCTYPE";
			}
			CBORObject info = mso.get("validityInfo");
			Instant from = Instant.parse(info.get("validFrom").UntagOne().AsString());
			Instant until = Instant.parse(info.get("validUntil").UntagOne().AsString());
			Instant now = Instant.now();
			return now.isBefore(from) || now.isAfter(until) ? "EXPIRED" : "VALID";
		}
		catch (RuntimeException e) {
			return "INVALID";
		}
	}

	/** Every sent field hashes to the value the issuer signed. */
	private static String digests(CBORObject mso, List<CredentialDto.ItemDto> items) {
		try {
			for (CredentialDto.ItemDto item : items) {
				CBORObject inner = itemMap(item);
				if (!item.elementIdentifier().equals(inner.get("elementIdentifier").AsString())) {
					return "MISMATCH";
				}
				CBORObject expected = mso.get("valueDigests").get(item.namespace())
						.get(CBORObject.FromObject(inner.get("digestID").AsInt32Value()));
				byte[] actual = DigitalIdIssuer.sha256(Base64.getDecoder().decode(item.bytes()));
				if (expected == null || !MessageDigest.isEqual(expected.GetByteString(), actual)) {
					return "MISMATCH";
				}
			}
			return "MATCH";
		}
		catch (RuntimeException e) {
			return "MISMATCH";
		}
	}

	/** The device key named in the signed MSO signed this nonce and field list. */
	private static String deviceSignature(CBORObject mso, byte[] nonce, String docType, List<String> ids, byte[] signature) {
		try {
			ECPublicKey deviceKey = EcKeys.fromCoseKey(mso.get("deviceKeyInfo").get("deviceKey"));
			return EcKeys.verify(deviceKey, deviceAuthentication(nonce, docType, ids), signature) ? "VALID" : "INVALID";
		}
		catch (RuntimeException e) {
			return "INVALID";
		}
	}

	/** Decodes IssuerSignedItemBytes (tag 24 around the item map). */
	private static CBORObject itemMap(CredentialDto.ItemDto item) {
		CBORObject wrapped = CBORObject.DecodeFromBytes(Base64.getDecoder().decode(item.bytes()));
		return CBORObject.DecodeFromBytes(wrapped.UntagOne().GetByteString());
	}

	/** Field value as plain JSON: text, true/false, or Base64 for bytes (the portrait). */
	private static Object displayValue(CBORObject value) {
		CBORObject v = value.isTagged() ? value.Untag() : value;
		if (v.getType() == CBORType.Boolean) {
			return v.AsBoolean();
		}
		if (v.getType() == CBORType.ByteString) {
			return Base64.getEncoder().encodeToString(v.GetByteString());
		}
		if (v.getType() == CBORType.TextString) {
			return v.AsString();
		}
		return v.toString();
	}
}
