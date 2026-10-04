# passport_validate

A Java server that checks whether ePassport chip data is genuine (ICAO 9303 Passive Authentication).

## Why

To mimic how Apple Wallet adds a Digital ID from a passport.
The phone reads the chip, and a server decides whether the data is real. The phone alone cannot be trusted with that decision.

## You need two repos

| Repo | Role |
|---|---|
| [**passport_read**](https://github.com/joonselim/passport_read) | iPhone app. Reads the chip and sends the data here |
| **passport_validate** (this one) | Java server. Checks the data |

You can also test this server alone with the fake passport samples below.

## What it checks

| Check | Question | Result |
|---|---|---|
| Data integrity | Do DG1 and DG2 match the hashes inside the SOD? | `MATCH` / `MISMATCH` |
| SOD signature | Is the SOD signed by the signer certificate inside it? | `VALID` / `INVALID` |
| Issuer trust | Was that signer certificate issued by a country certificate (CSCA) we trust? | `TRUSTED` / `UNVERIFIED` / `FAILED` |

`overall` is `PASS` when all three pass, `UNVERIFIED` when no CSCA is loaded, and `FAIL` otherwise.

## Structure

```
src/main/java/dev/joonselim/passport/
  api/      HTTP endpoints (GET /health, POST /verify)
  verify/   The three checks
  trust/    Loads CSCA certificates from csca/
  config/   Settings
src/test/   Tests with a fake passport
csca/       Put CSCA certificates here (not in git)
```

## Run

Requirements: Java 21.

```bash
./gradlew test       # run the tests
./gradlew bootRun    # start the server on http://localhost:8080
```

### Add country certificates (CSCA)

Without CSCA certificates, issuer trust is always `UNVERIFIED`.
Download the German BSI Master List (it includes about 120 countries), unzip it, and put the `.ml` file in `csca/`. Then restart the server.

https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html

### Try it without a passport

```bash
./gradlew exportSample   # writes fake passport files to samples/
curl -s -X POST localhost:8080/api/v1/passport/verify \
  -H 'Content-Type: application/json' --data @samples/synthetic.json
```

## API

`GET /api/v1/passport/health` returns `{"status":"ok","cscaCertificates":N}`.

`POST /api/v1/passport/verify` takes the raw chip files as Base64:

```json
{ "dg1": "...", "sod": "...", "dg2": "..." }
```

`dg2` is optional. Errors: `400` if a field is missing, `422` if the data is not a passport file.

## Libraries

- [JMRTD](https://jmrtd.org): reads passport files
- [Bouncy Castle](https://www.bouncycastle.org): signatures and certificates
- Spring Boot
