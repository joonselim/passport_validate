package dev.joonselim.passport.verify;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.stereotype.Component;

import dev.joonselim.passport.verify.CheckStatus.Integrity;

/** Check 1: hash DG1 and DG2 and compare them with the hashes stored in the SOD. */
@Component
public class IntegrityChecker {

	public record Result(Integrity status, String digestAlgorithm, Map<String, Integrity> dataGroups,
			Map<String, String> reasons) {
	}

	/** Compares every data group that was sent. */
	public Result check(SodInfo sod, PassportFiles files) {
		Map<String, Integrity> perGroup = new LinkedHashMap<>();
		Map<String, String> reasons = new LinkedHashMap<>();

		perGroup.put("DG1", compare(sod, 1, files.dg1(), reasons));
		if (files.dg2() != null) {
			perGroup.put("DG2", compare(sod, 2, files.dg2(), reasons));
		}
		else {
			perGroup.put("DG2", Integrity.NOT_PROVIDED);
		}

		boolean anyMismatch = perGroup.values().stream().anyMatch(s -> s == Integrity.MISMATCH);
		return new Result(anyMismatch ? Integrity.MISMATCH : Integrity.MATCH, sod.digestAlgorithm(), perGroup, reasons);
	}

	/** Hashes one data group (the whole file) and compares it with the SOD value. */
	private Integrity compare(SodInfo sod, int dgNumber, byte[] raw, Map<String, String> reasons) {
		String key = "DG" + dgNumber;
		byte[] expected = sod.dataGroupHashes().get(dgNumber);
		if (expected == null) {
			reasons.put(key, "SOD contains no hash for " + key);
			return Integrity.MISMATCH;
		}
		byte[] actual;
		try {
			actual = MessageDigest.getInstance(sod.digestAlgorithm()).digest(raw);
		}
		catch (NoSuchAlgorithmException e) {
			reasons.put(key, "unsupported digest algorithm " + sod.digestAlgorithm());
			return Integrity.MISMATCH;
		}
		if (MessageDigest.isEqual(expected, actual)) {
			return Integrity.MATCH;
		}
		reasons.put(key, "hash of provided " + key + " differs from SOD");
		return Integrity.MISMATCH;
	}
}
