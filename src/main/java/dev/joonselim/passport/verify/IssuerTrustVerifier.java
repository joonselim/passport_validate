package dev.joonselim.passport.verify;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.stereotype.Component;

import dev.joonselim.passport.trust.CscaTrustStore;
import dev.joonselim.passport.verify.CheckStatus.Trust;

/** Check 3: was the signer (DS) certificate issued by a trusted country certificate (CSCA)? */
@Component
public class IssuerTrustVerifier {

	public record Result(Trust status, String reason, String trustAnchorSubject) {
	}

	private final CscaTrustStore trustStore;

	public IssuerTrustVerifier(CscaTrustStore trustStore) {
		this.trustStore = trustStore;
	}

	/** Builds the chain DS -> CSCA. No CSCA loaded means UNVERIFIED. Revocation is not checked. */
	public Result verify(SodInfo sod) {
		if (sod.documentSigner().isEmpty()) {
			return new Result(Trust.FAILED, "SOD contains no Document Signer certificate", null);
		}
		List<X509Certificate> anchors = trustStore.certificates();
		if (anchors.isEmpty()) {
			return new Result(Trust.UNVERIFIED, "no CSCA certificates loaded", null);
		}
		X509Certificate ds = sod.documentSigner().get();
		try {
			CertificateFactory cf = CertificateFactory.getInstance("X.509");
			CertPath path = cf.generateCertPath(List.of(ds));
			Set<TrustAnchor> trustAnchors = anchors.stream()
					.map(c -> new TrustAnchor(c, null))
					.collect(Collectors.toSet());
			PKIXParameters params = new PKIXParameters(trustAnchors);
			params.setRevocationEnabled(false);
			CertPathValidator validator = CertPathValidator.getInstance("PKIX");
			PKIXCertPathValidatorResult result = (PKIXCertPathValidatorResult) validator.validate(path, params);
			String anchorSubject = result.getTrustAnchor().getTrustedCert().getSubjectX500Principal().getName();
			return new Result(Trust.TRUSTED, "chain built to CSCA " + anchorSubject, anchorSubject);
		}
		catch (CertPathValidatorException e) {
			return new Result(Trust.FAILED, "DS certificate does not chain to a trusted CSCA: " + e.getMessage(), null);
		}
		catch (Exception e) {
			return new Result(Trust.FAILED, e.getClass().getSimpleName() + ": " + e.getMessage(), null);
		}
	}
}
