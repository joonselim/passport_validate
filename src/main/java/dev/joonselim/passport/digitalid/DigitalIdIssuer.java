package dev.joonselim.passport.digitalid;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.interfaces.ECPublicKey;
import java.time.Clock;
import java.time.Instant;
import java.time.LocalDate;
import java.time.Period;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.jmrtd.lds.icao.DG1File;
import org.jmrtd.lds.icao.DG2File;
import org.jmrtd.lds.icao.MRZInfo;
import org.jmrtd.lds.iso19794.FaceImageInfo;
import org.jmrtd.lds.iso19794.FaceInfo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.upokecenter.cbor.CBORObject;

import dev.joonselim.passport.verify.PassportParseException;

/**
 * Builds a Digital ID in the ISO 18013-5 mdoc shape from a verified passport:
 * each field is a separately hashed item, and the issuer signs the list of hashes (the MSO)
 * together with the iPhone's public key. That key binds the ID to one device.
 */
@Component
public class DigitalIdIssuer {

	/** Document type and namespace of the Digital ID. */
	public static final String DOC_TYPE = "dev.joonselim.passportid.1";
	public static final String NAMESPACE = DOC_TYPE;

	/** One signed field: its name and its encoded bytes (IssuerSignedItemBytes). */
	public record Item(String namespace, String elementIdentifier, byte[] bytes) {
	}

	/** The issued ID: the issuer signature over the MSO, plus all fields. */
	public record Credential(String docType, byte[] issuerAuth, List<Item> items) {
	}

	private final IssuerKeys issuer;
	private final Clock clock;
	private final SecureRandom random = new SecureRandom();

	@Autowired
	public DigitalIdIssuer(IssuerKeys issuer) {
		this(issuer, Clock.systemUTC());
	}

	public DigitalIdIssuer(IssuerKeys issuer, Clock clock) {
		this.issuer = issuer;
		this.clock = clock;
	}

	/** Makes and signs the ID. dg1 and dg2 must already be verified. */
	public Credential issue(byte[] dg1, byte[] dg2, ECPublicKey deviceKey) {
		MRZInfo mrz = readMrz(dg1);
		LocalDate today = LocalDate.now(clock);
		LocalDate birth = mrzDate(mrz.getDateOfBirth(), today, true);
		LocalDate expiry = mrzDate(mrz.getDateOfExpiry(), today, false);
		int age = Period.between(birth, today).getYears();

		Map<String, CBORObject> fields = new LinkedHashMap<>();
		fields.put("family_name", CBORObject.FromObject(clean(mrz.getPrimaryIdentifier())));
		fields.put("given_name", CBORObject.FromObject(givenName(mrz)));
		fields.put("birth_date", fullDate(birth));
		fields.put("expiry_date", fullDate(expiry));
		fields.put("document_number", CBORObject.FromObject(clean(mrz.getDocumentNumber())));
		fields.put("nationality", CBORObject.FromObject(clean(mrz.getNationality())));
		fields.put("issuing_country", CBORObject.FromObject(clean(mrz.getIssuingState())));
		fields.put("sex", CBORObject.FromObject(sex(mrz)));
		portrait(dg2).ifPresent(p -> fields.put("portrait", CBORObject.FromObject(p)));
		fields.put("age_over_18", age >= 18 ? CBORObject.True : CBORObject.False);
		fields.put("age_over_21", age >= 21 ? CBORObject.True : CBORObject.False);

		List<Item> items = new ArrayList<>();
		CBORObject digests = CBORObject.NewOrderedMap();
		int digestId = 0;
		for (var field : fields.entrySet()) {
			byte[] salt = new byte[16];
			random.nextBytes(salt);
			CBORObject item = CBORObject.NewOrderedMap()
					.Add("digestID", digestId)
					.Add("random", salt)
					.Add("elementIdentifier", field.getKey())
					.Add("elementValue", field.getValue());
			byte[] itemBytes = CBORObject.FromObjectAndTag(item.EncodeToBytes(), 24).EncodeToBytes();
			digests.Add(digestId, sha256(itemBytes));
			items.add(new Item(NAMESPACE, field.getKey(), itemBytes));
			digestId++;
		}

		Instant now = clock.instant().truncatedTo(ChronoUnit.SECONDS);
		Instant passportEnd = expiry.atStartOfDay(ZoneOffset.UTC).toInstant();
		Instant validUntil = passportEnd.isBefore(now.plus(365, ChronoUnit.DAYS)) ? passportEnd : now.plus(365, ChronoUnit.DAYS);

		CBORObject mso = CBORObject.NewOrderedMap()
				.Add("version", "1.0")
				.Add("digestAlgorithm", "SHA-256")
				.Add("valueDigests", CBORObject.NewOrderedMap().Add(NAMESPACE, digests))
				.Add("deviceKeyInfo", CBORObject.NewOrderedMap().Add("deviceKey", EcKeys.coseKey(deviceKey)))
				.Add("docType", DOC_TYPE)
				.Add("validityInfo", CBORObject.NewOrderedMap()
						.Add("signed", tdate(now))
						.Add("validFrom", tdate(now))
						.Add("validUntil", tdate(validUntil)));
		byte[] msoBytes = CBORObject.FromObjectAndTag(mso.EncodeToBytes(), 24).EncodeToBytes();
		return new Credential(DOC_TYPE, Cose.sign1(msoBytes, issuer), items);
	}

	/** Passport expiry date from DG1, to refuse expired passports. */
	public LocalDate expiryDate(byte[] dg1) {
		return mrzDate(readMrz(dg1).getDateOfExpiry(), LocalDate.now(clock), false);
	}

	/** SHA-256 of some bytes. */
	public static byte[] sha256(byte[] data) {
		try {
			return MessageDigest.getInstance("SHA-256").digest(data);
		}
		catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException(e);
		}
	}

	/** Reads the MRZ from DG1. */
	private static MRZInfo readMrz(byte[] dg1) {
		try {
			return new DG1File(new ByteArrayInputStream(dg1)).getMRZInfo();
		}
		catch (Exception e) {
			throw new PassportParseException("EF.DG1 could not be parsed: " + e.getMessage());
		}
	}

	/** First face image in DG2 (usually JPEG 2000), if it can be read. */
	private static Optional<byte[]> portrait(byte[] dg2) {
		if (dg2 == null) {
			return Optional.empty();
		}
		try {
			DG2File file = new DG2File(new ByteArrayInputStream(dg2));
			for (FaceInfo face : file.getFaceInfos()) {
				for (FaceImageInfo image : face.getFaceImageInfos()) {
					try (InputStream in = image.getImageInputStream()) {
						return Optional.of(in.readAllBytes());
					}
				}
			}
		}
		catch (Exception ignored) {
			// No readable face image: the ID is issued without a portrait
		}
		return Optional.empty();
	}

	/** YYMMDD to a date. Birth dates in the future are moved back 100 years; expiry dates are 20YY. */
	private static LocalDate mrzDate(String yymmdd, LocalDate today, boolean birth) {
		int yy = Integer.parseInt(yymmdd.substring(0, 2));
		int year = 2000 + yy;
		if (birth && year > today.getYear()) {
			year -= 100;
		}
		return LocalDate.of(year, Integer.parseInt(yymmdd.substring(2, 4)), Integer.parseInt(yymmdd.substring(4, 6)));
	}

	/** Given names joined with spaces. */
	private static String givenName(MRZInfo mrz) {
		String[] parts = mrz.getSecondaryIdentifierComponents();
		return parts == null ? "" : clean(String.join(" ", parts));
	}

	/** M, F or X. */
	private static String sex(MRZInfo mrz) {
		if (mrz.getGender() == null) {
			return "X";
		}
		return switch (mrz.getGender()) {
			case MALE -> "M";
			case FEMALE -> "F";
			default -> "X";
		};
	}

	/** MRZ filler '<' to spaces, trimmed. */
	private static String clean(String s) {
		return s == null ? "" : s.replace('<', ' ').trim().replaceAll(" +", " ");
	}

	/** CBOR full-date (tag 1004), e.g. "1990-01-01". */
	private static CBORObject fullDate(LocalDate d) {
		return CBORObject.FromObjectAndTag(d.toString(), 1004);
	}

	/** CBOR date-time (tag 0), e.g. "2026-10-04T12:00:00Z". */
	private static CBORObject tdate(Instant t) {
		return CBORObject.FromObjectAndTag(t.toString(), 0);
	}
}
