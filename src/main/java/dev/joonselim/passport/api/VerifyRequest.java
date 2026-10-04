package dev.joonselim.passport.api;

import jakarta.validation.constraints.NotBlank;

/** Request body: the raw chip files as Base64. dg1 and sod are required, dg2 is optional. */
public record VerifyRequest(
		@NotBlank(message = "dg1 is required") String dg1,
		@NotBlank(message = "sod is required") String sod,
		String dg2) {
}
