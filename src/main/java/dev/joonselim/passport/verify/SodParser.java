package dev.joonselim.passport.verify;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Optional;

import org.jmrtd.lds.SODFile;
import org.springframework.stereotype.Component;

/** Reads the SOD file: the signed list of data group hashes. */
@Component
public class SodParser {

	/** Parses SOD bytes with JMRTD. */
	public SodInfo parse(byte[] sodBytes) {
		Tlv.requireTag(sodBytes, PassportFiles.SOD_TAG, "EF.SOD");
		byte[] cms = Tlv.value(sodBytes, PassportFiles.SOD_TAG, "EF.SOD");
		try {
			SODFile sod = new SODFile(new ByteArrayInputStream(sodBytes));
			X509Certificate ds = null;
			try {
				ds = sod.getDocSigningCertificate();
			}
			catch (RuntimeException ignored) {
				// Some countries leave out the DS certificate
			}
			return new SodInfo(
					sod.getDigestAlgorithm(),
					sod.getDigestEncryptionAlgorithm(),
					Collections.unmodifiableMap(sod.getDataGroupHashes()),
					Optional.ofNullable(ds),
					sod.getLDSVersion(),
					cms);
		}
		catch (IOException | RuntimeException e) {
			throw new PassportParseException("EF.SOD could not be parsed: " + e.getMessage(), e);
		}
	}
}
