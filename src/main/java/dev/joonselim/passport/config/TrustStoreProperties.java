package dev.joonselim.passport.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Folder with CSCA certificates. Setting: passport.csca.dir (default "csca"). */
@ConfigurationProperties(prefix = "passport.csca")
public record TrustStoreProperties(String dir) {
	public TrustStoreProperties {
		if (dir == null || dir.isBlank()) {
			dir = "csca";
		}
	}
}
