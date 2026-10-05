package dev.joonselim.passport.api;

import java.util.List;

/** What the iPhone shows a verifier (sent encrypted): the issuer signature, only the chosen fields, and the device signature. */
public record PresentRequest(String nonce, String docType, String issuerAuth, List<CredentialDto.ItemDto> items,
		String deviceSignature) {
}
