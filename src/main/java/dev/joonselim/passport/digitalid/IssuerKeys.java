package dev.joonselim.passport.digitalid;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import dev.joonselim.passport.config.BouncyCastleConfig;

/**
 * The Digital ID issuer: a P-256 key and a self-signed certificate.
 * Plays the role a country CSCA plays for passports. Created on first run in keys/.
 */
@Component
public class IssuerKeys {

	private static final Logger log = LoggerFactory.getLogger(IssuerKeys.class);

	private final PrivateKey privateKey;
	private final X509Certificate certificate;

	/** Used by Spring: loads the key and certificate files, or creates them on first run. */
	@Autowired
	public IssuerKeys(@Value("${passport.issuer.key-file:keys/issuer-p256.key}") String keyFile,
			@Value("${passport.issuer.cert-file:keys/issuer.cer}") String certFile) {
		BouncyCastleConfig.register();
		Path key = Path.of(keyFile);
		Path cert = Path.of(certFile);
		try {
			if (Files.exists(key) && Files.exists(cert)) {
				this.privateKey = KeyFactory.getInstance("EC")
						.generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(Files.readString(key).strip())));
				this.certificate = (X509Certificate) CertificateFactory.getInstance("X.509")
						.generateCertificate(new ByteArrayInputStream(Base64.getDecoder().decode(Files.readString(cert).strip())));
				log.info("Digital ID issuer loaded: {}", certificate.getSubjectX500Principal().getName());
			}
			else {
				KeyPair kp = newKeyPair();
				this.privateKey = kp.getPrivate();
				this.certificate = selfSigned(kp);
				write(key, kp.getPrivate().getEncoded());
				write(cert, certificate.getEncoded());
				log.info("Created a new Digital ID issuer key in {}", key);
			}
		}
		catch (IOException | GeneralSecurityException | IllegalArgumentException e) {
			throw new IllegalStateException("could not load or create the issuer key: " + e.getMessage(), e);
		}
	}

	/** For tests: a fresh in-memory issuer. */
	public static IssuerKeys inMemory() {
		try {
			KeyPair kp = newKeyPair();
			return new IssuerKeys(kp.getPrivate(), selfSigned(kp));
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	private IssuerKeys(PrivateKey privateKey, X509Certificate certificate) {
		this.privateKey = privateKey;
		this.certificate = certificate;
	}

	/** The issuer certificate. Verifiers trust this, like they trust a CSCA. */
	public X509Certificate certificate() {
		return certificate;
	}

	/** ES256 signature with the issuer key. */
	public byte[] sign(byte[] data) {
		return EcKeys.sign(privateKey, data);
	}

	/** New P-256 key pair. */
	private static KeyPair newKeyPair() throws GeneralSecurityException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		kpg.initialize(new ECGenParameterSpec("secp256r1"));
		return kpg.generateKeyPair();
	}

	/** Self-signed issuer certificate, valid for 5 years. */
	private static X509Certificate selfSigned(KeyPair kp) throws GeneralSecurityException {
		BouncyCastleConfig.register();
		try {
			X500Name name = new X500Name("CN=passport_validate demo issuer, O=passport_validate");
			Instant now = Instant.now();
			var builder = new JcaX509v3CertificateBuilder(name, new BigInteger(64, new SecureRandom()),
					Date.from(now.minus(1, ChronoUnit.DAYS)), Date.from(now.plus(5 * 365, ChronoUnit.DAYS)), name, kp.getPublic());
			builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
			var signer = new JcaContentSignerBuilder("SHA256withECDSA").setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build(kp.getPrivate());
			return new JcaX509CertificateConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.getCertificate(builder.build(signer));
		}
		catch (Exception e) {
			throw new GeneralSecurityException("could not create issuer certificate", e);
		}
	}

	/** Writes Base64 to a file readable only by the owner. */
	private static void write(Path file, byte[] data) throws IOException {
		if (file.toAbsolutePath().getParent() != null) {
			Files.createDirectories(file.toAbsolutePath().getParent());
		}
		Files.writeString(file, Base64.getEncoder().encodeToString(data) + "\n");
		try {
			Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
		}
		catch (UnsupportedOperationException ignored) {
			// Not a POSIX file system
		}
	}
}
