package dev.joonselim.passport.crypto;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContext;
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Encrypted channel with the iOS app (HPKE, RFC 9180).
 * Suite: X25519 + HKDF-SHA256 + ChaCha20-Poly1305, the same as CryptoKit's Curve25519_SHA256_ChachaPoly.
 */
@Component
public class HpkeChannel {

	private static final Logger log = LoggerFactory.getLogger(HpkeChannel.class);

	/** Context string mixed into the keys. Must match the iOS app. */
	public static final byte[] INFO = "passport_validate/v1".getBytes(StandardCharsets.UTF_8);
	/** Label for deriving the response key. Must match the iOS app. */
	public static final byte[] RESPONSE_LABEL = "response".getBytes(StandardCharsets.UTF_8);

	private static final byte[] NO_AAD = new byte[0];
	private static final int NONCE_LENGTH = 12;
	private static final int RESPONSE_KEY_LENGTH = 32;

	/** Decrypted request, plus the key used to encrypt the answer. */
	public record Opened(byte[] plaintext, byte[] responseKey) {
	}

	private final AsymmetricCipherKeyPair keyPair;
	private final byte[] publicKey;

	/** Used by Spring: loads the private key file, or creates it on first run. */
	@Autowired
	public HpkeChannel(@Value("${passport.hpke.key-file:keys/hpke-x25519.key}") String keyFile) {
		this(loadOrCreate(Path.of(keyFile)));
	}

	/** Uses the given 32-byte X25519 private key. */
	public HpkeChannel(byte[] privateKey) {
		this.publicKey = new X25519PrivateKeyParameters(privateKey, 0).generatePublicKey().getEncoded();
		this.keyPair = suite().deserializePrivateKey(privateKey, publicKey);
	}

	/** The HPKE settings both sides use. */
	public static HPKE suite() {
		return new HPKE(HPKE.mode_base, HPKE.kem_X25519_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_CHACHA20_POLY1305);
	}

	/** Raw 32-byte public key. The iOS app pins this. */
	public byte[] publicKey() {
		return publicKey.clone();
	}

	/** Short id of the public key: first 8 bytes of SHA-256, in hex. */
	public String keyId() {
		return keyId(publicKey);
	}

	/** Same id calculation, for any public key. */
	public static String keyId(byte[] publicKey) {
		try {
			byte[] hash = MessageDigest.getInstance("SHA-256").digest(publicKey);
			return HexFormat.of().formatHex(hash, 0, 8);
		}
		catch (GeneralSecurityException e) {
			throw new IllegalStateException(e);
		}
	}

	/** Decrypts a request and derives the response key from it. */
	public Opened open(byte[] enc, byte[] ciphertext) {
		try {
			HPKEContext context = suite().setupBaseR(enc, keyPair, INFO);
			byte[] plaintext = context.open(NO_AAD, ciphertext);
			return new Opened(plaintext, context.export(RESPONSE_LABEL, RESPONSE_KEY_LENGTH));
		}
		catch (InvalidCipherTextException | RuntimeException e) {
			throw new SealedPayloadException("could not decrypt the request (was it encrypted with this server's key?)");
		}
	}

	/** Encrypts the answer with ChaCha20-Poly1305. Output: nonce + ciphertext + tag (CryptoKit's "combined" format). */
	public static byte[] sealResponse(byte[] responseKey, byte[] plaintext) {
		byte[] nonce = new byte[NONCE_LENGTH];
		new SecureRandom().nextBytes(nonce);
		byte[] sealed = chacha(Cipher.ENCRYPT_MODE, responseKey, nonce, plaintext);
		byte[] out = Arrays.copyOf(nonce, NONCE_LENGTH + sealed.length);
		System.arraycopy(sealed, 0, out, NONCE_LENGTH, sealed.length);
		return out;
	}

	/** Reverse of sealResponse. The app does this; here it is used by tests. */
	public static byte[] openResponse(byte[] responseKey, byte[] combined) {
		byte[] nonce = Arrays.copyOfRange(combined, 0, NONCE_LENGTH);
		byte[] sealed = Arrays.copyOfRange(combined, NONCE_LENGTH, combined.length);
		return chacha(Cipher.DECRYPT_MODE, responseKey, nonce, sealed);
	}

	/** ChaCha20-Poly1305 with the JDK's built-in cipher. */
	private static byte[] chacha(int mode, byte[] key, byte[] nonce, byte[] input) {
		try {
			Cipher cipher = Cipher.getInstance("ChaCha20-Poly1305");
			cipher.init(mode, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
			return cipher.doFinal(input);
		}
		catch (GeneralSecurityException e) {
			throw new SealedPayloadException("response encryption failed: " + e.getMessage());
		}
	}

	/** Reads the Base64 private key from the file, or makes a new one and saves it (owner read/write only). */
	private static byte[] loadOrCreate(Path file) {
		try {
			if (Files.exists(file)) {
				byte[] key = Base64.getDecoder().decode(Files.readString(file).strip());
				log.info("HPKE key loaded from {}", file);
				return key;
			}
			byte[] key = new byte[32];
			new SecureRandom().nextBytes(key);
			if (file.toAbsolutePath().getParent() != null) {
				Files.createDirectories(file.toAbsolutePath().getParent());
			}
			Files.writeString(file, Base64.getEncoder().encodeToString(key) + "\n");
			try {
				Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"));
			}
			catch (UnsupportedOperationException ignored) {
				// Not a POSIX file system (e.g. Windows)
			}
			log.info("Created a new HPKE key in {}. Put the public key from GET /health into the iOS app.", file);
			return key;
		}
		catch (IOException | IllegalArgumentException e) {
			throw new IllegalStateException("could not load or create the HPKE key file " + file + ": " + e.getMessage(), e);
		}
	}
}
