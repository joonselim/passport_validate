package dev.joonselim.passport.verify;

import java.security.cert.X509Certificate;
import java.util.Collection;

import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Component;

import dev.joonselim.passport.verify.CheckStatus.Signature;

/** Check 2: verify the SOD signature with the signer (DS) certificate inside it. */
@Component
public class SignatureVerifier {

	public record Result(Signature status, String algorithm, String reason) {
	}

	/** Bouncy Castle checks the signed hash and the signature itself. */
	public Result verify(SodInfo sod) {
		if (sod.documentSigner().isEmpty()) {
			return new Result(Signature.INVALID, sod.signatureAlgorithm(), "SOD contains no Document Signer certificate");
		}
		X509Certificate ds = sod.documentSigner().get();
		try {
			CMSSignedData cms = new CMSSignedData(sod.cmsSignedData());
			Collection<SignerInformation> signers = cms.getSignerInfos().getSigners();
			if (signers.isEmpty()) {
				return new Result(Signature.INVALID, sod.signatureAlgorithm(), "SOD has no SignerInfo");
			}
			var verifier = new JcaSimpleSignerInfoVerifierBuilder()
					.setProvider(BouncyCastleProvider.PROVIDER_NAME)
					.build(ds);
			for (SignerInformation signer : signers) {
				if (!signer.verify(verifier)) {
					return new Result(Signature.INVALID, sod.signatureAlgorithm(), "signature does not verify with DS public key");
				}
			}
			return new Result(Signature.VALID, sod.signatureAlgorithm(), null);
		}
		catch (Exception e) {
			return new Result(Signature.INVALID, sod.signatureAlgorithm(), e.getClass().getSimpleName() + ": " + e.getMessage());
		}
	}
}
