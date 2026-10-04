package dev.joonselim.passport.config;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;

/** Registers the Bouncy Castle crypto library at startup. */
@Configuration
public class BouncyCastleConfig {

	@PostConstruct
	void registerProvider() {
		register();
	}

	/** Adds Bouncy Castle once. Safe to call many times. */
	public static void register() {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}
}
