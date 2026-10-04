package dev.joonselim.passport.trust;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.stream.Stream;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import dev.joonselim.passport.config.TrustStoreProperties;

/** Loads CSCA certificates from the csca/ folder at startup. Empty folder means UNVERIFIED. */
@Component
public class CscaTrustStore {

	private static final Logger log = LoggerFactory.getLogger(CscaTrustStore.class);

	private final List<X509Certificate> certificates;
	private final Path directory;

	/** Used by Spring: folder from the settings. */
	@Autowired
	public CscaTrustStore(TrustStoreProperties props) {
		this(Path.of(props.dir()));
	}

	/** Loads every certificate file in the folder. */
	public CscaTrustStore(Path directory) {
		this.directory = directory;
		this.certificates = List.copyOf(load(directory));
		log.info("CSCA trust store: {} certificate(s) loaded from {}", certificates.size(), directory.toAbsolutePath());
	}

	/** For tests: use these certificates directly. */
	public CscaTrustStore(List<X509Certificate> certificates) {
		this.directory = null;
		this.certificates = List.copyOf(certificates);
	}

	/** All loaded CSCA certificates. */
	public List<X509Certificate> certificates() {
		return certificates;
	}

	/** Folder the certificates came from. */
	public Path directory() {
		return directory;
	}

	/** Reads .cer, .crt, .der, .pem and .ml files. Bad files are skipped. */
	private static List<X509Certificate> load(Path dir) {
		List<X509Certificate> out = new ArrayList<>();
		if (!Files.isDirectory(dir)) {
			log.warn("CSCA directory {} does not exist", dir.toAbsolutePath());
			return out;
		}
		try (Stream<Path> files = Files.list(dir)) {
			files.filter(Files::isRegularFile).sorted().forEach(p -> {
				String name = p.getFileName().toString().toLowerCase(Locale.ROOT);
				try {
					if (name.endsWith(".ml")) {
						List<X509Certificate> certs = MasterListParser.parse(Files.readAllBytes(p));
						out.addAll(certs);
						log.info("  {} → {} CSCA certificate(s)", p.getFileName(), certs.size());
					}
					else if (name.endsWith(".cer") || name.endsWith(".crt") || name.endsWith(".der") || name.endsWith(".pem")) {
						List<X509Certificate> certs = readX509(p);
						out.addAll(certs);
						log.info("  {} → {} certificate(s)", p.getFileName(), certs.size());
					}
				}
				catch (IOException | CertificateException e) {
					log.warn("  skipping {}: {}", p.getFileName(), e.getMessage());
				}
			});
		}
		catch (IOException e) {
			log.warn("could not list CSCA directory {}: {}", dir, e.getMessage());
		}
		return out;
	}

	/** Reads one or more certificates from a file. */
	private static List<X509Certificate> readX509(Path p) throws IOException, CertificateException {
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		List<X509Certificate> out = new ArrayList<>();
		try (InputStream in = Files.newInputStream(p)) {
			for (Certificate c : cf.generateCertificates(in)) {
				out.add((X509Certificate) c);
			}
		}
		return out;
	}
}
