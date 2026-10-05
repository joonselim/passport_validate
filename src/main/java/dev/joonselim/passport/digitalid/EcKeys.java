package dev.joonselim.passport.digitalid;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;

import com.upokecenter.cbor.CBORObject;

import dev.joonselim.passport.config.BouncyCastleConfig;

/** P-256 key helpers: key formats and ES256 signatures in raw r||s form (what COSE and CryptoKit use). */
public final class EcKeys {

	private static final String CURVE = "secp256r1";
	private static final String ES256 = "SHA256withPLAIN-ECDSA";

	private EcKeys() {
	}

	/** Public key from the 65-byte uncompressed form (0x04 || x || y), as sent by the iPhone. */
	public static ECPublicKey fromX963(byte[] x963) {
		BouncyCastleConfig.register();
		try {
			ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(CURVE);
			var point = spec.getCurve().decodePoint(x963);
			return (ECPublicKey) KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME)
					.generatePublic(new org.bouncycastle.jce.spec.ECPublicKeySpec(point, spec));
		}
		catch (GeneralSecurityException | RuntimeException e) {
			throw new DigitalIdException("bad_device_key", "device public key is not a valid P-256 key");
		}
	}

	/** 65-byte uncompressed form of a public key. */
	public static byte[] toX963(ECPublicKey key) {
		byte[] out = new byte[65];
		out[0] = 0x04;
		System.arraycopy(fixed32(key.getW().getAffineX()), 0, out, 1, 32);
		System.arraycopy(fixed32(key.getW().getAffineY()), 0, out, 33, 32);
		return out;
	}

	/** COSE_Key map for a P-256 public key: {1: 2 (EC2), -1: 1 (P-256), -2: x, -3: y}. */
	public static CBORObject coseKey(ECPublicKey key) {
		return CBORObject.NewOrderedMap()
				.Add(1, 2)
				.Add(-1, 1)
				.Add(-2, fixed32(key.getW().getAffineX()))
				.Add(-3, fixed32(key.getW().getAffineY()));
	}

	/** Public key from a COSE_Key map. */
	public static ECPublicKey fromCoseKey(CBORObject coseKey) {
		byte[] x = coseKey.get(CBORObject.FromObject(-2)).GetByteString();
		byte[] y = coseKey.get(CBORObject.FromObject(-3)).GetByteString();
		byte[] x963 = new byte[65];
		x963[0] = 0x04;
		System.arraycopy(x, 0, x963, 1, 32);
		System.arraycopy(y, 0, x963, 33, 32);
		return fromX963(x963);
	}

	/** ES256 signature, 64 bytes (r || s). */
	public static byte[] sign(PrivateKey key, byte[] data) {
		BouncyCastleConfig.register();
		try {
			Signature s = Signature.getInstance(ES256, BouncyCastleProvider.PROVIDER_NAME);
			s.initSign(key);
			s.update(data);
			return s.sign();
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	/** Checks a 64-byte ES256 signature. Returns false for any problem. */
	public static boolean verify(PublicKey key, byte[] data, byte[] signature) {
		BouncyCastleConfig.register();
		try {
			Signature s = Signature.getInstance(ES256, BouncyCastleProvider.PROVIDER_NAME);
			s.initVerify(key);
			s.update(data);
			return s.verify(signature);
		}
		catch (GeneralSecurityException | RuntimeException e) {
			return false;
		}
	}

	/** Big integer as exactly 32 bytes. */
	private static byte[] fixed32(BigInteger n) {
		byte[] raw = n.toByteArray();
		byte[] out = new byte[32];
		int copy = Math.min(raw.length, 32);
		System.arraycopy(raw, raw.length - copy, out, 32 - copy, copy);
		return out;
	}
}
