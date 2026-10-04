package dev.joonselim.passport.verify;

import java.util.Arrays;

/** Small helper for the tag + length header at the start of each chip file. */
final class Tlv {

	private Tlv() {
	}

	/** First byte is the file's tag. */
	static int tagOf(byte[] file) {
		if (file == null || file.length < 2) {
			throw new PassportParseException("file too short");
		}
		return file[0] & 0xFF;
	}

	/** Fails if the file does not start with the expected tag. */
	static void requireTag(byte[] file, int expectedTag, String name) {
		int tag = tagOf(file);
		if (tag != expectedTag) {
			throw new PassportParseException(String.format(
					"%s: expected tag 0x%02X but found 0x%02X", name, expectedTag, tag));
		}
	}

	/** Returns the bytes inside the outer tag. */
	static byte[] value(byte[] file, int expectedTag, String name) {
		requireTag(file, expectedTag, name);
		int idx = 1;
		int first = file[idx++] & 0xFF;
		int len;
		if (first < 0x80) {
			len = first;
		}
		else {
			int n = first & 0x7F;
			if (n < 1 || n > 3 || idx + n > file.length) {
				throw new PassportParseException(name + ": unsupported length encoding");
			}
			len = 0;
			for (int i = 0; i < n; i++) {
				len = (len << 8) | (file[idx++] & 0xFF);
			}
		}
		if (idx + len > file.length) {
			throw new PassportParseException(name + ": declared length exceeds data");
		}
		return Arrays.copyOfRange(file, idx, idx + len);
	}
}
