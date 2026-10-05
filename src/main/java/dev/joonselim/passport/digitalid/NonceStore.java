package dev.joonselim.passport.digitalid;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** One-time random values that expire. Used for issuance challenges and verifier requests. Kept in memory only. */
public final class NonceStore<T> {

	private record Entry<T>(T value, Instant expires) {
	}

	private final ConcurrentHashMap<String, Entry<T>> entries = new ConcurrentHashMap<>();
	private final SecureRandom random = new SecureRandom();
	private final Duration lifetime;
	private final Clock clock;

	public NonceStore(Duration lifetime) {
		this(lifetime, Clock.systemUTC());
	}

	public NonceStore(Duration lifetime, Clock clock) {
		this.lifetime = lifetime;
		this.clock = clock;
	}

	/** Makes a new 32-byte nonce and remembers the value attached to it. */
	public byte[] create(T value) {
		Instant now = clock.instant();
		entries.values().removeIf(e -> e.expires().isBefore(now));
		byte[] nonce = new byte[32];
		random.nextBytes(nonce);
		entries.put(key(nonce), new Entry<>(value, now.plus(lifetime)));
		return nonce;
	}

	/** Uses up a nonce. Empty if it is unknown, already used, or expired. */
	public Optional<T> consume(byte[] nonce) {
		Entry<T> e = entries.remove(key(nonce));
		if (e == null || e.expires().isBefore(clock.instant())) {
			return Optional.empty();
		}
		return Optional.of(e.value());
	}

	/** How long a nonce stays valid. */
	public Duration lifetime() {
		return lifetime;
	}

	private static String key(byte[] nonce) {
		return Base64.getEncoder().encodeToString(nonce);
	}
}
