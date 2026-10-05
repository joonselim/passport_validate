package dev.joonselim.passport.api;

import java.util.Map;

/** The verifier's decision, each check, and the fields it received (only when accepted). */
public record PresentResult(String result, Map<String, String> checks, String issuer, Map<String, Object> disclosed) {
}
