package dev.joonselim.passport.trust;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.joonselim.passport.fixture.SyntheticPassport;

/** Loading CSCA certificates from a folder. */
class CscaTrustStoreTest {

	@Test
	void loadsDerAndPemCertificates_andIgnoresJunk(@TempDir Path dir) throws Exception {
		SyntheticPassport a = SyntheticPassport.create("UTO", "CSCA A");
		SyntheticPassport b = SyntheticPassport.create("XXA", "CSCA B");

		Files.write(dir.resolve("a.cer"), a.cscaCert.getEncoded());
		String pem = "-----BEGIN CERTIFICATE-----\n"
				+ java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(b.cscaCert.getEncoded())
				+ "\n-----END CERTIFICATE-----\n";
		Files.writeString(dir.resolve("b.pem"), pem);
		Files.writeString(dir.resolve("README.md"), "ignored");
		Files.writeString(dir.resolve("broken.cer"), "not a certificate");

		CscaTrustStore store = new CscaTrustStore(dir);

		assertThat(store.certificates()).containsExactlyInAnyOrder(a.cscaCert, b.cscaCert);
	}

	@Test
	void missingDirectory_isEmpty(@TempDir Path dir) {
		assertThat(new CscaTrustStore(dir.resolve("nope")).certificates()).isEmpty();
	}
}
