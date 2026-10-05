package dev.joonselim.passport.api;

import java.util.Base64;

import org.springframework.stereotype.Component;

import dev.joonselim.passport.crypto.HpkeChannel;
import dev.joonselim.passport.verify.PassportParseException;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.json.JsonMapper;

/** Opens an HPKE-encrypted JSON request and encrypts the JSON answer with the matching response key. */
@Component
public class SealedJson {

	/** The decrypted request, plus the key for the answer. */
	public record Opened<T>(T value, byte[] responseKey) {
	}

	private final HpkeChannel channel;
	private final JsonMapper json;

	public SealedJson(HpkeChannel channel, JsonMapper json) {
		this.channel = channel;
		this.json = json;
	}

	/** Decrypts and parses the request body as the given type. */
	public <T> Opened<T> open(SealedRequest request, Class<T> type) {
		HpkeChannel.Opened opened = channel.open(ApiBase64.decode(request.enc(), "enc"),
				ApiBase64.decode(request.ciphertext(), "ciphertext"));
		try {
			return new Opened<>(json.readValue(opened.plaintext(), type), opened.responseKey());
		}
		catch (JacksonException e) {
			throw new PassportParseException("decrypted payload is not valid JSON");
		}
	}

	/** Turns the answer into JSON and encrypts it. */
	public SealedResponse seal(Opened<?> opened, Object answer) {
		byte[] sealed = HpkeChannel.sealResponse(opened.responseKey(), json.writeValueAsBytes(answer));
		return new SealedResponse(Base64.getEncoder().encodeToString(sealed));
	}
}
