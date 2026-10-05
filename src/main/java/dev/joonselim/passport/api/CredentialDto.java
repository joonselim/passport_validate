package dev.joonselim.passport.api;

import java.util.Base64;
import java.util.List;

import dev.joonselim.passport.digitalid.DigitalIdIssuer;

/** A Digital ID as JSON: the issuer signature (COSE_Sign1) and each signed field, all Base64. */
public record CredentialDto(String docType, String issuerAuth, List<ItemDto> items) {

	/** One signed field. bytes = IssuerSignedItemBytes (CBOR). */
	public record ItemDto(String namespace, String elementIdentifier, String bytes) {
	}

	/** Converts the issuer's result to JSON form. */
	public static CredentialDto of(DigitalIdIssuer.Credential c) {
		Base64.Encoder b64 = Base64.getEncoder();
		return new CredentialDto(c.docType(), b64.encodeToString(c.issuerAuth()),
				c.items().stream().map(i -> new ItemDto(i.namespace(), i.elementIdentifier(), b64.encodeToString(i.bytes()))).toList());
	}
}
