package dev.joonselim.passport.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Base64;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

import dev.joonselim.passport.fixture.SyntheticPassport;
import dev.joonselim.passport.trust.CscaTrustStore;

/** HTTP tests against a running server. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VerifyControllerTest {

	static SyntheticPassport passport;

	@BeforeAll
	static void fixture() throws Exception {
		passport = SyntheticPassport.create();
	}

	@TestConfiguration
	static class TrustedCsca {
		@Bean
		@Primary
		CscaTrustStore testStore() {
			return new CscaTrustStore(List.of(passport.cscaCert));
		}
	}

	@Value("${local.server.port}")
	int port;

	private RestClient client() {
		return RestClient.create("http://localhost:" + port);
	}

	private static String b64(byte[] b) {
		return Base64.getEncoder().encodeToString(b);
	}

	@Test
	void verify_genuine_returnsPass() {
		Map<?, ?> body = client().post().uri("/api/v1/passport/verify")
				.body(Map.of("dg1", b64(passport.dg1), "sod", b64(passport.sod), "dg2", b64(passport.dg2)))
				.retrieve().body(Map.class);

		assertThat(body.get("overall")).isEqualTo("PASS");
		Map<?, ?> checks = (Map<?, ?>) body.get("checks");
		assertThat(((Map<?, ?>) checks.get("dataIntegrity")).get("status")).isEqualTo("MATCH");
		assertThat(((Map<?, ?>) checks.get("signature")).get("status")).isEqualTo("VALID");
		assertThat(((Map<?, ?>) checks.get("issuerTrust")).get("status")).isEqualTo("TRUSTED");
	}

	@Test
	void verify_tampered_returnsFail() {
		Map<?, ?> body = client().post().uri("/api/v1/passport/verify")
				.body(Map.of("dg1", b64(SyntheticPassport.tamper(passport.dg1)), "sod", b64(passport.sod)))
				.retrieve().body(Map.class);

		assertThat(body.get("overall")).isEqualTo("FAIL");
	}

	@Test
	void verify_badBase64_is422() {
		ResponseEntity<Map> resp = client().post().uri("/api/v1/passport/verify")
				.body(Map.of("dg1", "@@not-base64@@", "sod", b64(passport.sod)))
				.exchange((req, res) -> ResponseEntity.status(res.getStatusCode())
						.body(res.bodyTo(Map.class)));

		assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
		assertThat(resp.getBody().get("error")).isEqualTo("unparseable_input");
	}

	@Test
	void verify_missingSod_is400() {
		ResponseEntity<Map> resp = client().post().uri("/api/v1/passport/verify")
				.body(Map.of("dg1", b64(passport.dg1)))
				.exchange((req, res) -> ResponseEntity.status(res.getStatusCode())
						.body(res.bodyTo(Map.class)));

		assertThat(resp.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
		assertThat(resp.getBody().get("error")).isEqualTo("invalid_request");
	}
}
