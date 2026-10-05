package dev.joonselim.passport.fixture;

import org.bouncycastle.crypto.hpke.HPKE;
import org.bouncycastle.crypto.hpke.HPKEContextWithEncapsulation;

import dev.joonselim.passport.crypto.HpkeChannel;

/** Plays the iOS app in tests: seals a message to the server's public key. */
public record HpkeTestClient(byte[] enc, byte[] ciphertext, byte[] responseKey) {

	/** Encrypts the message for the given server, like the app does. */
	public static HpkeTestClient seal(HpkeChannel server, byte[] message) throws Exception {
		HPKE hpke = HpkeChannel.suite();
		HPKEContextWithEncapsulation ctx = hpke.setupBaseS(hpke.deserializePublicKey(server.publicKey()), HpkeChannel.INFO);
		byte[] ct = ctx.seal(new byte[0], message);
		return new HpkeTestClient(ctx.getEncapsulation(), ct, ctx.export(HpkeChannel.RESPONSE_LABEL, 32));
	}
}
