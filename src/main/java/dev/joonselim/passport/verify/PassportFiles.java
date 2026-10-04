package dev.joonselim.passport.verify;

import java.util.Optional;

/** Raw chip files: DG1 and SOD are required, DG2 is optional. */
public record PassportFiles(byte[] dg1, byte[] sod, byte[] dg2) {

	public static final int DG1_TAG = 0x61;
	public static final int DG2_TAG = 0x75;
	public static final int SOD_TAG = 0x77;

	/** DG2 if it was sent. */
	public Optional<byte[]> dg2Optional() {
		return Optional.ofNullable(dg2);
	}
}
