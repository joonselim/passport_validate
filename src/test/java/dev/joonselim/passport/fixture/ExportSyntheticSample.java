package dev.joonselim.passport.fixture;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;

/** Writes fake passport JSON files to samples/ for testing with curl. Run: ./gradlew exportSample */
public final class ExportSyntheticSample {

	/** Writes synthetic.json, synthetic-tampered-dg1.json and synthetic-csca.cer. */
	public static void main(String[] args) throws Exception {
		Path json = Path.of(args.length > 0 ? args[0] : "samples/synthetic.json");
		Path cer = Path.of(args.length > 1 ? args[1] : "samples/synthetic-csca.cer");
		Path tampered = json.resolveSibling("synthetic-tampered-dg1.json");

		SyntheticPassport p = SyntheticPassport.create();
		Files.createDirectories(json.toAbsolutePath().getParent());
		Files.writeString(json, toJson(p.dg1, p.sod, p.dg2));
		Files.writeString(tampered, toJson(SyntheticPassport.tamper(p.dg1), p.sod, p.dg2));
		Files.write(cer, p.cscaCert.getEncoded());

		System.out.println("wrote " + json);
		System.out.println("wrote " + tampered);
		System.out.println("wrote " + cer + "  (copy into csca/ to get TRUSTED)");
	}

	/** Same JSON shape the iOS app sends. */
	private static String toJson(byte[] dg1, byte[] sod, byte[] dg2) {
		Base64.Encoder b64 = Base64.getEncoder();
		return """
				{
				  "dg1": "%s",
				  "sod": "%s",
				  "dg2": "%s"
				}
				""".formatted(b64.encodeToString(dg1), b64.encodeToString(sod), b64.encodeToString(dg2));
	}
}
