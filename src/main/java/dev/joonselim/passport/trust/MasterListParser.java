package dev.joonselim.passport.trust;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import dev.joonselim.passport.config.BouncyCastleConfig;

/**
 * Reads an ICAO master list (.ml) and returns the CSCA certificates inside.
 * The list's own signature is not checked.
 */
public final class MasterListParser {

	private MasterListParser() {
	}

	/** .ml file bytes to a list of certificates. */
	public static List<X509Certificate> parse(byte[] masterList) throws IOException {
		// This can run before the Bouncy Castle config, so register it here too.
		BouncyCastleConfig.register();
		try {
			CMSSignedData cms = new CMSSignedData(masterList);
			byte[] content = (byte[]) cms.getSignedContent().getContent();
			ASN1Sequence seq = ASN1Sequence.getInstance(content);
			ASN1Set certSet = ASN1Set.getInstance(seq.getObjectAt(1));
			JcaX509CertificateConverter converter = new JcaX509CertificateConverter()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME);
			List<X509Certificate> out = new ArrayList<>(certSet.size());
			for (ASN1Encodable enc : certSet) {
				out.add(converter.getCertificate(new X509CertificateHolder(Certificate.getInstance(enc))));
			}
			return out;
		}
		catch (CMSException | java.security.cert.CertificateException | RuntimeException e) {
			throw new IOException("not a CSCA master list: " + e.getMessage(), e);
		}
	}
}
