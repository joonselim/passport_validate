package dev.joonselim.passport.crypto;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import dev.joonselim.passport.fixture.HpkeTestClient;

/** Encrypt as the app would, decrypt on the server, and back. */
class HpkeChannelTest {

	private static HpkeChannel newServer() {
		byte[] key = new byte[32];
		new SecureRandom().nextBytes(key);
		return new HpkeChannel(key);
	}

	@Test
	void requestAndResponse_roundTrip() throws Exception {
		HpkeChannel server = newServer();
		byte[] message = "{\"dg1\":\"...\"}".getBytes(StandardCharsets.UTF_8);

		HpkeTestClient sent = HpkeTestClient.seal(server, message);
		HpkeChannel.Opened opened = server.open(sent.enc(), sent.ciphertext());

		assertThat(opened.plaintext()).isEqualTo(message);
		assertThat(opened.responseKey()).isEqualTo(sent.responseKey());

		byte[] answer = "{\"overall\":\"PASS\"}".getBytes(StandardCharsets.UTF_8);
		byte[] sealedAnswer = HpkeChannel.sealResponse(opened.responseKey(), answer);
		assertThat(HpkeChannel.openResponse(sent.responseKey(), sealedAnswer)).isEqualTo(answer);
	}

	@Test
	void sealedForAnotherServer_cannotBeOpened() throws Exception {
		HpkeTestClient sent = HpkeTestClient.seal(newServer(), "secret".getBytes(StandardCharsets.UTF_8));

		assertThatThrownBy(() -> newServer().open(sent.enc(), sent.ciphertext()))
				.isInstanceOf(SealedPayloadException.class);
	}

	@Test
	void tamperedCiphertext_cannotBeOpened() throws Exception {
		HpkeChannel server = newServer();
		HpkeTestClient sent = HpkeTestClient.seal(server, "secret".getBytes(StandardCharsets.UTF_8));
		sent.ciphertext()[0] ^= 0x01;

		assertThatThrownBy(() -> server.open(sent.enc(), sent.ciphertext()))
				.isInstanceOf(SealedPayloadException.class);
	}

	@Test
	void keyFile_isCreatedOnce_andReused(@TempDir Path dir) {
		Path file = dir.resolve("keys/hpke.key");

		String first = new HpkeChannel(file.toString()).keyId();
		String second = new HpkeChannel(file.toString()).keyId();

		assertThat(Files.exists(file)).isTrue();
		assertThat(second).isEqualTo(first).hasSize(16);
	}
}
