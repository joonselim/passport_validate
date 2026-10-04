package dev.joonselim.passport.verify;

/** Result values for each check. */
public final class CheckStatus {

	private CheckStatus() {
	}

	/** Do the data hashes match the SOD? */
	public enum Integrity {
		MATCH, MISMATCH, NOT_PROVIDED
	}

	/** Is the SOD signature valid? */
	public enum Signature {
		VALID, INVALID
	}

	/** Was the signer certificate issued by a known country (CSCA)? */
	public enum Trust {
		TRUSTED, UNVERIFIED, FAILED
	}

	/** Final result. */
	public enum Overall {
		PASS, FAIL, UNVERIFIED
	}
}
