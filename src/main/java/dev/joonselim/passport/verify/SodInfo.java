package dev.joonselim.passport.verify;

import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;

/** The parts of the SOD the checks need: hash algorithm, stored hashes, signer certificate. */
public record SodInfo(
		String digestAlgorithm,
		String signatureAlgorithm,
		Map<Integer, byte[]> dataGroupHashes,
		Optional<X509Certificate> documentSigner,
		String ldsVersion,
		byte[] cmsSignedData) {
}
