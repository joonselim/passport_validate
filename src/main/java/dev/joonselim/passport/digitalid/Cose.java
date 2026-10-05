package dev.joonselim.passport.digitalid;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import com.upokecenter.cbor.CBORObject;

/** COSE_Sign1 (RFC 9052) with ES256, as used for the mdoc issuer signature. */
public final class Cose {

	private static final int HEADER_ALG = 1;
	private static final int ALG_ES256 = -7;
	private static final int HEADER_X5CHAIN = 33;

	private Cose() {
	}

	/** Signs the payload. Result: [protected, unprotected {x5chain: cert}, payload, signature]. */
	public static byte[] sign1(byte[] payload, IssuerKeys issuer) {
		byte[] protectedHeader = CBORObject.NewOrderedMap().Add(HEADER_ALG, ALG_ES256).EncodeToBytes();
		CBORObject unprotectedHeader;
		try {
			unprotectedHeader = CBORObject.NewOrderedMap().Add(HEADER_X5CHAIN, issuer.certificate().getEncoded());
		}
		catch (CertificateEncodingException e) {
			throw new IllegalStateException(e);
		}
		byte[] signature = issuer.sign(toBeSigned(protectedHeader, payload));
		return CBORObject.NewArray().Add(protectedHeader).Add(unprotectedHeader).Add(payload).Add(signature).EncodeToBytes();
	}

	/** Returns the payload if it was signed by the trusted issuer, otherwise null. */
	public static byte[] verify1(byte[] sign1, X509Certificate trustedIssuer) {
		try {
			CBORObject array = CBORObject.DecodeFromBytes(sign1);
			if (array.isTagged()) {
				array = array.UntagOne();
			}
			byte[] protectedHeader = array.get(0).GetByteString();
			CBORObject unprotectedHeader = array.get(1);
			byte[] payload = array.get(2).GetByteString();
			byte[] signature = array.get(3).GetByteString();

			int alg = CBORObject.DecodeFromBytes(protectedHeader).get(CBORObject.FromObject(HEADER_ALG)).AsInt32Value();
			if (alg != ALG_ES256) {
				return null;
			}
			CBORObject x5chain = unprotectedHeader.get(CBORObject.FromObject(HEADER_X5CHAIN));
			if (x5chain != null && !Arrays.equals(x5chain.GetByteString(), trustedIssuer.getEncoded())) {
				return null;
			}
			return EcKeys.verify(trustedIssuer.getPublicKey(), toBeSigned(protectedHeader, payload), signature) ? payload : null;
		}
		catch (Exception e) {
			return null;
		}
	}

	/** Sig_structure: ["Signature1", protected, external_aad (empty), payload]. */
	private static byte[] toBeSigned(byte[] protectedHeader, byte[] payload) {
		return CBORObject.NewArray().Add("Signature1").Add(protectedHeader).Add(new byte[0]).Add(payload).EncodeToBytes();
	}
}
