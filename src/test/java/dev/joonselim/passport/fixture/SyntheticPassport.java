package dev.joonselim.passport.fixture;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.jmrtd.lds.SODFile;
import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.MRZInfo;

import dev.joonselim.passport.config.BouncyCastleConfig;
import net.sf.scuba.data.Gender;

/** Builds a fake passport (test CSCA, test DS, signed SOD) so tests run without a real passport. */
public final class SyntheticPassport {

	public final X509Certificate cscaCert;
	public final X509Certificate dsCert;
	public final byte[] dg1;
	public final byte[] dg2;
	public final byte[] sod;

	private SyntheticPassport(X509Certificate cscaCert, X509Certificate dsCert, byte[] dg1, byte[] dg2, byte[] sod) {
		this.cscaCert = cscaCert;
		this.dsCert = dsCert;
		this.dg1 = dg1;
		this.dg2 = dg2;
		this.sod = sod;
	}

	/** Fake passport for a test country. */
	public static SyntheticPassport create() throws Exception {
		return create("UTO", "Test CSCA");
	}

	/** Fake passport for the given country and CSCA name. */
	public static SyntheticPassport create(String country, String cscaName) throws Exception {
		BouncyCastleConfig.register();

		// MRZ uses 3-letter country codes, certificates use 2-letter codes
		String dnCountry = country.substring(0, 2);
		KeyPair cscaKeys = rsa();
		X500Name cscaDn = new X500Name("C=" + dnCountry + ", O=" + cscaName + ", CN=" + cscaName);
		X509Certificate csca = certificate(cscaDn, cscaDn, cscaKeys.getPublic(), cscaKeys.getPrivate(), true);

		KeyPair dsKeys = rsa();
		X500Name dsDn = new X500Name("C=" + dnCountry + ", O=" + cscaName + ", CN=Test Document Signer 1");
		X509Certificate ds = certificate(dsDn, cscaDn, dsKeys.getPublic(), cscaKeys.getPrivate(), false);

		MRZInfo mrz = new MRZInfo("P", country, "HONG", "GILDONG", "M12345678", country,
				"900101", Gender.MALE, "300101", "");
		byte[] dg1 = new DG1File(mrz).getEncoded();

		// DG2 content doesn't matter here, only its hash
		byte[] faceBlob = new byte[512];
		new SecureRandom().nextBytes(faceBlob);
		byte[] dg2 = wrap(0x75, faceBlob);

		MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
		Map<Integer, byte[]> hashes = new LinkedHashMap<>();
		hashes.put(1, sha256.digest(dg1));
		hashes.put(2, sha256.digest(dg2));

		SODFile sodFile = new SODFile("SHA-256", "SHA256withRSA", hashes, dsKeys.getPrivate(), ds);
		return new SyntheticPassport(csca, ds, dg1, dg2, sodFile.getEncoded());
	}

	/** Copy of the file with one byte flipped, to fake tampering. */
	public static byte[] tamper(byte[] file) {
		byte[] copy = file.clone();
		int idx = copy.length - 1;
		copy[idx] ^= 0x01;
		return copy;
	}

	/** New RSA key pair. */
	private static KeyPair rsa() throws Exception {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		kpg.initialize(2048);
		return kpg.generateKeyPair();
	}

	/** Makes a test certificate (CA or signer). */
	private static X509Certificate certificate(X500Name subject, X500Name issuer, java.security.PublicKey pub,
			PrivateKey signer, boolean ca) throws Exception {
		Instant now = Instant.now();
		X509v3CertificateBuilder b = new JcaX509v3CertificateBuilder(
				issuer,
				new BigInteger(64, new SecureRandom()),
				Date.from(now.minus(1, ChronoUnit.DAYS)),
				Date.from(now.plus(ca ? 15 * 365 : 11 * 365, ChronoUnit.DAYS)),
				subject,
				pub);
		b.addExtension(Extension.basicConstraints, true, new BasicConstraints(ca));
		b.addExtension(Extension.keyUsage, true,
				new KeyUsage(ca ? KeyUsage.keyCertSign | KeyUsage.cRLSign : KeyUsage.digitalSignature));
		var contentSigner = new JcaContentSignerBuilder("SHA256withRSA")
				.setProvider(BouncyCastleProvider.PROVIDER_NAME).build(signer);
		return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
				.getCertificate(b.build(contentSigner));
	}

	/** Wraps bytes in a tag + length header. */
	private static byte[] wrap(int tag, byte[] value) {
		byte[] out = new byte[value.length + 4];
		out[0] = (byte) tag;
		out[1] = (byte) 0x82;
		out[2] = (byte) (value.length >> 8);
		out[3] = (byte) value.length;
		System.arraycopy(value, 0, out, 4, value.length);
		return out;
	}
}
