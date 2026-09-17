# ECDAT — Synthetic Enterprise Test Harness ("Meridian Financial Group")

**Status:** DESIGN PROPOSAL — not canonical until reviewed and frozen.
**Scope of this document:** the test harness only. It does not change the ECDAT architecture, and where the harness exposes gaps in the architecture those are listed as OPEN QUESTIONS, not silently fixed.

Labels used: **FACT** (spec/standard-level, stable), **VERIFY** (believed true, must be checked against a primary source before build), **INFERENCE** (engineering reasoning, not tested), **ASSUMPTION**, **DESIGN DECISION**, **OPEN QUESTION**.

---

## 0. Verdict first — what's wrong with the request as stated

The request is sound in direction but has four traps. The design below is built around them.

1. **A self-authored corpus is circular.** If the same people who write the Semgrep/YARA rules also plant the crypto, the harness measures "did we detect what we already knew we could detect." Recall numbers from it are an **upper bound**, not an accuracy claim. The architecture doc (Part 12) already says scanning your own toy repo gets discounted. The harness is therefore a **regression and honesty-testing tool**, and it must be paired with (a) a blind-planted holdout set and (b) manual enumeration on real OSS targets. Never quote harness recall on stage as "ECDAT accuracy."
2. **Ground truth ≠ expected output.** "RSA-OAEP is used here" is the planted truth. But with the architecture's adapter set, the *correct* ECDAT output for a config-driven `Cipher.getInstance(algo)` is `algorithm: UNKNOWN` (Directive 4, Part 2). A manifest that only records planted truth would *reward* false certainty. So the manifest has two layers: **planted truth** (the oracle) and **expected observation** (what an honest tool with this adapter set should report). This is the most important design decision in this document.
3. **Mosca/context is not discoverable, so it can't be "detected."** Data lifetime, criticality and exposure-to-business are DECLARED inputs. The harness can only test that ECDAT (a) ingests them, (b) labels them DECLARED, (c) computes deterministically, (d) varies correctly under sensitivity. There is no "Mosca accuracy" metric. Don't invent one.
4. **The harness can easily become bigger than the tool.** Five domains × multiple languages × six surfaces is a scope trap for a student team. The design is tiered (Section 3): Tier A is the minimum that exercises every canonical-demo transition; Tiers B/C add adversarial and coverage cases. Build Tier A first. Cut C before cutting A.

Also flagged: the request lists **SSH and IPsec**. The current adapter set (Part 2) has **no SSH or IPsec collector**. Planting them is still correct — they become **coverage tests**: the right output is either config-level evidence (if Directive 4's config resolution is built) or an explicit NOT_OBSERVED / unsupported entry in the visibility matrix. Silently reporting nothing is the failure being tested.

---

## 1. Design principles for the harness

| # | Principle | Type |
|---|---|---|
| H1 | **Ground truth lives outside the scan root.** The scanner is pointed at `targets/`; `ground-truth/` is a sibling it is never given. Prevents leakage (a scanner reading the manifest and "discovering" everything). | DESIGN DECISION |
| H2 | **No harness-specific logic in ECDAT.** No rule, path, filename, hostname or identifier from the harness may appear in scanner code or rules. Enforced by a CI grep + mutation test (Section 8.6). | DESIGN DECISION |
| H3 | **No key material committed to git.** All keys/certs are generated at build time by `harness/build/generate-pki.sh`. The build emits a *generated* lockfile of fingerprints that the ground truth references by **role**, not by fingerprint. | DESIGN DECISION |
| H4 | **Every planted asset has an expected epistemic state per surface.** | DESIGN DECISION |
| H5 | **Negative controls are mandatory:** non-security crypto (checksums), dead code, test vectors, documentation mentions, already-migrated PQC assets, and a zero-crypto repo. | DESIGN DECISION |
| H6 | **Network isolation.** All live endpoints run on an internal Docker network with no egress. The only authorised TLS/SSH targets are harness containers (exercises the Part 1 allow-list + consent flag). | DESIGN DECISION |
| H7 | **Declared context values are synthetic parameters, not regulatory claims.** Lifetimes in this harness are test inputs; the cited-lookup-table requirement from Part 6 still applies to the product. | DESIGN DECISION |
| H8 | **Versioned snapshots.** The harness has two git tags (`v1`, `v2`) that differ in known ways, to test temporal inventory/delta (Directive 9). | DESIGN DECISION |

---

## 2. The fictional enterprise

**Meridian Financial Group** — mid-sized Indian fintech/lender, ~2,000 staff. Five business domains, one shared infrastructure layer, one internal PKI, one (mocked) cloud KMS, one (emulated) HSM.

| Domain | Systems | Languages | Why it's in the harness |
|---|---|---|---|
| **Payments** | `payment-gateway` (Spring Boot), `settlement-batch` (legacy C), HAProxy TLS terminator | Java, C | Config-driven crypto, keystores, TLS termination at a different layer than the app, legacy 3DES, HSM reference |
| **HR** | `hr-portal` (Flask) | Python | *Indirect* crypto (Fernet hides AES+HMAC), JWT via nested deps, SAML signing cert near expiry, statically bundled OpenSSL in wheels |
| **Research** | `datalake-sync` (Go, stripped static binary), `notebook-gateway` (Node) | Go, JS | Stripped static binary (YARA test), long data lifetime (Mosca-interesting), non-security SHA-1 |
| **Customer Services** | `customer-portal` (TypeScript/Express), `ivr-connector` (vendor binary, no source), `legacy-statements` (COBOL, unsupported) | TS, C (binary only), COBOL | Vendored multi-algorithm library, expired cert, no-source binary, unsupported-language coverage |
| **Infrastructure** | Internal CA, bastion SSH, site-to-site IPsec, Kubernetes/Helm manifests, JVM security config, cloud KMS metadata, SoftHSM2 token, PQC-hybrid edge proxy | configs | SSH/IPsec coverage tests, config-evidence tests, KMS/HSM metadata, PQC negative controls, secret-redaction tests |

---

## 3. Tiering (build order)

| Tier | Contents | Purpose | Must-have? |
|---|---|---|---|
| **A — canonical chain** | Payments end-to-end: Java source → pom deps → container image → PKCS12 keystore → HAProxy TLS endpoint → declared context. Plus the internal CA. Plus one negative control. | Exercises every transition of Directive 12's demo chain | MUST (MVP) |
| **B — multi-surface breadth** | HR, Research, Customer Services (except COBOL), KMS mock, PQC edge, `v2` snapshot | Classification breadth, binary detection, indirect crypto, drift | IMPORTANT |
| **C — adversarial / coverage** | SSH, IPsec, COBOL, SoftHSM2, obfuscated/constant-free cases, traps, blind holdout | Tests the visibility matrix and honesty metrics | IMPORTANT FOR TRUST — but cut before A |

Rough size: **~48 planted assets, ~12 traps/negative controls, ~30 relationship edges.** That is enough to be non-trivial without the harness becoming a second project. (INFERENCE — adjust after Tier A is built.)

---

## 4. Directory structure

```
ecdat-harness/
├── README.md                          # purpose, safety notice, build/run
├── harness/
│   ├── build/
│   │   ├── generate-pki.sh            # creates all keys/certs; never commit output
│   │   ├── build-binaries.sh          # compiles Go/C binaries with fixed flags
│   │   ├── build-images.sh            # docker build for all images, pinned bases
│   │   └── pki-lock.generated.json    # OUTPUT: role → fingerprint/serial/notAfter (gitignored)
│   ├── compose/
│   │   └── docker-compose.yml         # internal network, no egress
│   ├── mutate/
│   │   └── mutate.py                  # renames paths/identifiers for overfitting test
│   └── eval/
│       ├── score.py                   # compares ECDAT output vs ground truth
│       └── metrics.md                 # metric definitions (Section 8)
│
├── ground-truth/                      # NEVER passed to the scanner
│   ├── schema/
│   │   ├── asset.schema.json
│   │   └── relationship.schema.json
│   ├── assets/                        # one YAML per planted asset
│   │   ├── PAY-001.yaml ...
│   ├── relationships.yaml
│   ├── traps.yaml                     # negative controls & expected non-findings
│   ├── context.declared.yaml          # apps, owners, criticality, data class, lifetimes
│   ├── scenarios.mosca.yaml           # Z scenarios + expected verdicts
│   ├── recommendations.oracle.yaml    # acceptable option SETS per asset/policy
│   ├── visibility.expected.yaml       # expected coverage/blind-spot entries
│   └── deltas/v1_to_v2.yaml           # expected drift
│
├── holdout/                           # planted by a teammate who doesn't write rules
│   └── (sealed until evaluation; separate ground truth kept offline)
│
└── targets/                           # THE ONLY THING ECDAT IS POINTED AT
    ├── payments/
    │   ├── payment-gateway/           # Java 21 (pinned exact build), Spring Boot
    │   │   ├── pom.xml
    │   │   ├── Dockerfile
    │   │   ├── src/main/java/com/meridian/pay/
    │   │   │   ├── crypto/KeyWrapService.java      # Cipher.getInstance(cfg) — config-driven
    │   │   │   ├── crypto/WebhookSigner.java       # Mac HmacSHA256 literal
    │   │   │   ├── crypto/TokenVault.java          # AES/GCM/NoPadding literal
    │   │   │   ├── crypto/LegacyCardHash.java      # DEAD CODE: MD5, never called (trap)
    │   │   │   └── config/CryptoProperties.java
    │   │   ├── src/main/resources/application.yml   # pay.keywrap.transformation
    │   │   ├── src/test/java/.../VectorsTest.java  # AES test vectors (trap)
    │   │   └── keystore/                            # generated: gateway.p12
    │   ├── settlement-batch/          # legacy C, OpenSSL EVP API
    │   │   ├── Makefile
    │   │   ├── src/settle.c           # DES-EDE3-CBC, RSA-1024 signing
    │   │   ├── src/hsm_client.c       # PKCS#11 C_Sign call via SoftHSM2
    │   │   └── conf/softhsm2.conf
    │   └── edge-lb/
    │       ├── haproxy.cfg            # TLS terminates HERE, not in the app
    │       └── Dockerfile
    ├── hr/
    │   └── hr-portal/
    │       ├── requirements.txt       # top-level only
    │       ├── poetry.lock            # full nested tree
    │       ├── Dockerfile
    │       ├── app/security/tokens.py         # PyJWT RS256
    │       ├── app/security/vault.py          # Fernet (indirect AES-128-CBC + HMAC)
    │       ├── app/security/passwords.py      # bcrypt
    │       ├── app/security/sso.py            # SAML signing via xmlsec (cert path from env)
    │       └── deploy/.env.example            # SAML_SIGNING_ALG=rsa-sha256
    ├── research/
    │   ├── datalake-sync/             # Go, stripped static binary shipped in image
    │   │   ├── go.mod / go.sum
    │   │   ├── cmd/sync/main.go       # X25519 ECDH, Ed25519, AES-256-GCM
    │   │   ├── internal/cache/key.go  # sha1 for cache keys (non-security, trap-ish)
    │   │   └── Dockerfile             # multi-stage, final image = scratch + binary
    │   └── notebook-gateway/
    │       ├── package.json / package-lock.json
    │       └── src/auth.js            # jsonwebtoken ES256
    ├── customer/
    │   ├── customer-portal/           # TypeScript/Express
    │   │   ├── package.json / package-lock.json
    │   │   ├── src/crypto/legacy.ts   # createCipheriv('aes-256-cbc', key, STATIC_IV)
    │   │   ├── src/server.ts          # https.createServer, expired cert
    │   │   ├── vendor/node-forge/     # VENDORED copy — no manifest entry
    │   │   └── docs/SECURITY.md       # mentions "RSA" and "3DES" in prose (trap)
    │   ├── ivr-connector/
    │   │   └── bin/ivr-connector      # prebuilt ELF, dynamically linked libcrypto, NOT stripped
    │   └── legacy-statements/
    │       └── STMTENC.cbl            # COBOL calling mainframe crypto services (unsupported)
    ├── infrastructure/
    │   ├── pki/                       # generated: root, intermediates, leaves, CRL
    │   ├── ssh/bastion/sshd_config
    │   ├── ipsec/swanctl.conf
    │   ├── jvm/java.security.override
    │   ├── k8s/
    │   │   ├── helm/payment-gateway/values.yaml   # tls.minVersion, cipher list
    │   │   └── secrets/pay-tls-secret.yaml        # base64 FAKE private key (redaction test)
    │   ├── cloud/kms-inventory.mock.json          # describe-key-shaped metadata, no material
    │   └── pqc-edge/
    │       ├── nginx.conf             # hybrid X25519MLKEM768 group
    │       └── Dockerfile             # OpenSSL >= 3.5
    └── controls/
        └── no-crypto-service/         # zero-crypto repo (Python), negative control
```

**Why `targets/` is flat by domain rather than by language:** the architecture principle is *observation surfaces over languages*. Languages appear inside apps; the scanner should not need to know the directory taxonomy. The mutation test (8.6) will scramble these names anyway.

---

## 5. Representative files

Short excerpts only — enough to fix the behaviour each file is meant to test. Full files are built during Tier A/B.

### 5.1 Payments — config-driven crypto (the headline hard case)

`KeyWrapService.java`
```java
// Algorithm is NOT a literal here. It comes from application.yml.
public byte[] wrap(SecretKey dek, PublicKey kek) throws GeneralSecurityException {
    Cipher c = Cipher.getInstance(props.getKeywrapTransformation());
    c.init(Cipher.WRAP_MODE, kek);
    return c.wrap(dek);
}
```
`application.yml`
```yaml
pay:
  keywrap:
    transformation: "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
server:
  ssl:
    key-store: classpath:keystore/gateway.p12
    key-store-type: PKCS12
```
**Tests:** Semgrep alone → call site, `algorithm: UNKNOWN`. With config-chain resolution (Directive 4) → `algorithm: RSA-OAEP` as INFERRED (evidence: yml key + property binding), never KNOWN from source alone. Purpose: key transport (declared by `WRAP_MODE`) — this is one of the rare source cases where purpose *is* locally visible. (INFERENCE — whether a rule should extract purpose from `WRAP_MODE` is an OPEN QUESTION.)

`WebhookSigner.java` — literal `Mac.getInstance("HmacSHA256")` → KNOWN at source level, confidence per Part 3 table.

`LegacyCardHash.java` — `MessageDigest.getInstance("MD5")` in a class with **no callers**. Expected: finding reported, flagged as possibly unreachable; must not raise the asset to "in use."

### 5.2 Payments — legacy C

`settle.c`
```c
EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);   /* 3DES-CBC, file encryption */
RSA *r = RSA_new(); /* 1024-bit key loaded from conf, deprecated API */
EVP_DigestSignInit(mctx, NULL, EVP_sha1(), NULL, pkey);       /* RSA-SHA1 signing */
```
**Tests:** Semgrep C coverage (VERIFY current support level), dynamic symbol detection in the compiled binary, deprecated-API use under OpenSSL 3 (compiles with warnings / `-DOPENSSL_API_COMPAT`).

`hsm_client.c` — `C_Sign(session, ...)` with mechanism `CKM_ECDSA` against a SoftHSM2 token.
**Tests:** the algorithm lives in the HSM token. Source shows the mechanism constant; the token's key object (EC P-256, label `settle-sign`) is only visible via PKCS#11 enumeration. If the PKCS#11 metadata reader isn't built → expected visibility entry `HSM: NOT_OBSERVED`.

### 5.3 Payments — TLS termination at the LB

`haproxy.cfg`
```
frontend pay_in
    bind *:8443 ssl crt /etc/haproxy/certs/pay-edge.pem ssl-min-ver TLSv1.2 ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384
    default_backend gateway
backend gateway
    server gw payment-gateway:8080          # plaintext behind the LB
```
**Tests:** the wire shows the LB's ECDSA P-256 cert, *not* the RSA key in `gateway.p12`. A tool that merges "the RSA in the app" with "the cert on the wire" fails (Part 5). Expected relationship: `edge-lb —terminates-tls-for→ payment-gateway` = config_declared / DECLARED (from `haproxy.cfg`), never observed.

### 5.4 HR — indirect crypto

`vault.py`
```python
from cryptography.fernet import Fernet
f = Fernet(os.environ["HR_VAULT_KEY"])
token = f.encrypt(payload)
```
**FACT (Fernet spec):** Fernet = AES-128-CBC + HMAC-SHA256. No algorithm name appears in the code.
**Tests:** does the tool know library semantics (`Fernet` → AES-128-CBC/HMAC-SHA256), and does it label that as INFERRED-from-library-semantics rather than observed? AES-128 → Grover tier "increase size" — a genuine quantum-tier classification case hidden behind an abstraction.

`poetry.lock` includes `pyjwt[crypto]` → `cryptography` → `cffi`. **VERIFY:** `cryptography` manylinux wheels statically bundle OpenSSL, so the image contains an OpenSSL build that no OS package manager lists. Expected: Trivy sees `cryptography` (package), OS scan does not see *that* OpenSSL; binary/YARA on the `.so` may. Tests nested-dependency and hidden-provider handling.

`.env.example` — `SAML_SIGNING_ALG=rsa-sha256` → config evidence for SAML signing, purpose = signature, corroborated by the SAML cert's `keyUsage=digitalSignature`.

### 5.5 Research — stripped static Go binary

`build-binaries.sh`
```sh
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o out/datalake-sync ./cmd/sync
```
Final image is `FROM scratch` + binary. No package manager DB → Trivy's OS scan finds nothing; **VERIFY** whether Trivy reads Go build info embedded in the binary (it historically does for Go binaries; `-s -w` strips symbols, not build info — test it).
**Tests:** YARA constants — AES S-box (FACT: distinctive), SHA-256 init constants. X25519 and Ed25519 have fewer distinctive table constants (the curve prime/base point may still appear) — expected lower recall. That's fine; record it.

`internal/cache/key.go` — `sha1.Sum([]byte(path))` for cache keys. **Trap:** crypto present, security function = none. Expected: finding with `purpose: non-security` or `UNKNOWN`; must **not** appear in the quantum-risk queue as a signing/integrity asset (Directive 1).

### 5.6 Customer Services

`legacy.ts` — `createCipheriv('aes-256-cbc', key, STATIC_IV)`. Inventory truth: AES-256-CBC (quantum tier: not affected). Misuse (static IV) is **out of scope** for the inventory; recorded in the manifest as `misuse_note`, not scored.

`vendor/node-forge/` — a vendored copy with no `package.json` entry. **FACT:** node-forge implements RSA, AES, 3DES, HMAC, SHA-1/256, etc. Tests "one library provides many algorithms": expected output = *capability* (library present, many algorithms possible) + *usage* only where call sites exist. A tool that lists all 15 forge algorithms as used assets fails.

`server.ts` — HTTPS with a cert whose `notAfter` is in the past at build time. Expected: lifecycle state `EXPIRED`.

`ivr-connector` — prebuilt ELF (built from private source that is **not** in `targets/`), dynamically linked to `libcrypto.so.3`, unstripped, calls `EVP_aes_128_gcm`, `ECDSA_do_sign`. Tests binary-only evidence: symbols → capability/likely-use, confidence ~0.40 per Part 3.

`STMTENC.cbl` — COBOL calling mainframe crypto callable services (**VERIFY** exact ICSF service names before writing). **VERIFY:** Semgrep has no COBOL support. Expected output: `unsupported_language` entry in the visibility matrix with the file path. Reporting "0 assets" without that entry is a failure.

### 5.7 Infrastructure

`sshd_config` (bastion)
```
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
KexAlgorithms diffie-hellman-group14-sha1,curve25519-sha256,mlkem768x25519-sha256
HostKeyAlgorithms ssh-rsa,ssh-ed25519
Ciphers aes128-ctr,chacha20-poly1305@openssh.com
MACs hmac-sha1,hmac-sha2-256
```
**VERIFY:** `mlkem768x25519-sha256` requires OpenSSH ≥ 9.9; `ssh-rsa` (SHA-1) is disabled by default in modern OpenSSH and must be explicitly re-enabled for the legacy case. Mixed legacy + PQC in one config is deliberate: tests per-algorithm classification inside a single config.

`swanctl.conf`
```
connections {
  dc-to-dr {
    version = 2
    proposals = aes256-sha256-modp2048
    children { net { esp_proposals = aes128-sha1-modp1024 } }
    local { auth = pubkey  certs = ipsec-gw.pem }
  }
}
```
Config-only (no live tunnel — would need `NET_ADMIN`; not worth it). Tests config evidence: DH MODP-1024 and MODP-2048 (Shor-broken), AES-128 (Grover), SHA-1 (integrity use).

`java.security.override`
```
jdk.tls.disabledAlgorithms=SSLv3, RC4, DES, MD5withRSA, DH keySize < 1024
```
Deliberately *weaker* than JDK defaults (re-enables 3DES/TLS1.0 by omission). Tests Java security configuration as evidence that changes what the payment-gateway can negotiate. (INFERENCE: this is exactly the kind of thing Directive 4 asks for; whether ECDAT resolves it is OPEN.)

`k8s/secrets/pay-tls-secret.yaml` — contains a base64 **harness-generated throwaway** private key. Expected: finding "private key material present" + location; **material redacted** in DB, UI, CBOM, logs (Part 9, Directive 10).

`cloud/kms-inventory.mock.json` — shaped like AWS KMS `DescribeKey` output (**VERIFY** field names against AWS docs): one `RSA_4096` SIGN_VERIFY key, one `SYMMETRIC_DEFAULT` key, one `ECC_NIST_P256` key, rotation flags. Labelled **mock** in the manifest; it tests the parser/normaliser, not cloud access.

`pqc-edge/nginx.conf`
```
ssl_protocols TLSv1.3;
ssl_ecdh_curve X25519MLKEM768:X25519;
ssl_certificate /certs/edge-mldsa65.pem;   # optional: ML-DSA-65 leaf if tooling supports it
```
**VERIFY:** OpenSSL 3.5 (Apr 2025) added ML-KEM/ML-DSA/SLH-DSA and the hybrid group; nginx must be built against it. Whether **sslyze** reports hybrid groups is unknown — **test it** (Section 8.3). **Negative control:** this endpoint must *not* land in the "replace" queue.

---

## 6. Internal PKI plan (generated, never committed)

| Role | Key | Sig alg | Validity | Lifecycle state at build | keyUsage / EKU | Purpose of the case |
|---|---|---|---|---|---|---|
| `root-ca` | RSA-4096 | sha256WithRSA | 20 y | VALID | keyCertSign, cRLSign | Long-lived root → SLH-DSA/LMS recommendation path |
| `int-ca-ecc` | ECDSA P-384 | ecdsa-with-SHA384 | 10 y | VALID | keyCertSign | Mixed-algorithm chain |
| `int-ca-legacy` | RSA-2048 | sha1WithRSA | 10 y | VALID | keyCertSign | SHA-1-signed CA (VERIFY OpenSSL 3 will issue under chosen seclevel) |
| `pay-edge` | ECDSA P-256 | ecdsa-with-SHA256 | 90 d | VALID | digitalSignature / serverAuth | LB cert on the wire |
| `gateway-p12` | RSA-2048 | sha256WithRSA | 1 y | VALID | digitalSignature, keyEncipherment / serverAuth | In-app keystore, not on the wire |
| `hr-saml-sign` | RSA-2048 | sha256WithRSA | 2 y | EXPIRING (<30 d) | digitalSignature | Near-expiry lifecycle |
| `customer-portal` | RSA-2048 | sha256WithRSA | 1 y | EXPIRED | serverAuth | Expired |
| `settle-legacy` | RSA-1024 | sha1WithRSA | 5 y | VALID | digitalSignature | Legacy weak; TLS use may be refused at default seclevel (VERIFY — may need `@SECLEVEL=0`) |
| `ipsec-gw` | RSA-3072 | sha256WithRSA | 3 y | VALID | digitalSignature | IPsec auth, config-only |
| `revoked-api` | ECDSA P-256 | ecdsa-with-SHA256 | 1 y | REVOKED (in CRL) | serverAuth | Revocation state from CRL |
| `selfsigned-dev` | RSA-2048 | sha256WithRSA | 10 y | SELF-SIGNED | none | Unchained cert |
| `edge-mldsa65` | ML-DSA-65 | ML-DSA-65 | 90 d | VALID | digitalSignature | PQC negative control (optional; VERIFY tooling) |
| `jwt-signing` | ECDSA P-256 (JWK/PEM) | — | n/a | key only | — | Research JWT ES256 |

Keystores: `gateway.p12` (PKCS12), one `truststore.jks` (legacy JKS format) for parser coverage.

`pki-lock.generated.json` maps role → SHA-256 fingerprint, serial, notBefore/notAfter. `score.py` joins ECDAT output to ground truth **through this file**, so ground truth stays stable across regenerations. Lifecycle states are relative to the scan timestamp; the scorer must evaluate them against the lock file, not wall-clock guesses.

---

## 7. Ground-truth manifest

### 7.1 Asset schema (`asset.schema.json`, summarised)

```yaml
id: PAY-001
tier: A
domain: payments
application: payment-gateway
planted_truth:                      # the oracle — what actually exists
  algorithm_family: RSA
  algorithm: RSA-OAEP
  parameters: { key_bits: 2048, oaep_hash: SHA-256, mgf1_hash: provider-dependent }
  # SunJCE (default in harness): MGF1 uses SHA-1 when no OAEPParameterSpec is passed.
  # Bouncy Castle / Conscrypt: MGF1 uses SHA-256. The transformation string does NOT fix MGF1.
  primitive: pke                    # CycloneDX 1.6 enum (VERIFY against canonical schema)
  crypto_functions: [encrypt, decrypt]
  purpose: key-transport
  security_function: true           # false for checksums/cache keys
  reachable: true                   # false for dead code
  provider: SunJCE                  # or OpenSSL / BoringSSL / HSM / KMS / unknown
  quantum_tier: shor-broken         # shor-broken | grover-weakened | not-affected | pqc
locations:
  - surface: source
    path: payments/payment-gateway/src/main/java/.../KeyWrapService.java
    lines: [18, 20]
  - surface: configuration
    path: payments/payment-gateway/src/main/resources/application.yml
    key: pay.keywrap.transformation
expected_observation:               # what an HONEST tool should say
  governed_by: CFG-001              # see Section 14
  state_matrix: section-14.3        # states A-G, one fixture variant each
  must_not:
    - "algorithm state KNOWN from source alone"
    - "merge with gateway-p12 certificate asset"
declared_context:                   # DECLARED — cannot be discovered
  business_criticality: critical
  data_class: payment-card
  data_lifetime_years: 7            # synthetic parameter (H7)
  exposure: internal                # app is behind edge-lb
  environment: prod
migration:
  estimated_migration_years: 3      # synthetic Y
  constraints: [hsm-backed-kek-planned, pci-scope]
  oracle_ref: REC-PAY-001
misuse_note: null
```

### 7.2 Full planted-asset inventory

Legend — **Q**: S = Shor-broken, G = Grover-weakened, N = not affected, P = PQC, — = non-security. **Crit**: C/H/M/L. **Exp**: Ext = internet-facing, Int = internal. **X** = declared data lifetime (years, synthetic). **Expected** = the honest-tool expectation under the MVP adapter set (source, certs/TLS, image/packages, binary+YARA).

| ID | Tier | Domain / App | Surface | Planted truth | Purpose | Q | Crit | Exp | X | Expected (MVP adapters) |
|---|---|---|---|---|---|---|---|---|---|---|
| PAY-001 | A | pay / gateway | src+config | RSA-OAEP-2048 (config-driven) | key transport | S | C | Int | 7 | algorithm UNKNOWN (INFERRED only with config resolution) |
| PAY-002 | A | pay / gateway | src | HMAC-SHA256 literal | webhook integrity | N | H | Ext | 1 | KNOWN, purpose UNKNOWN from Semgrep (MAC ⇒ integrity is INFERENCE) |
| PAY-003 | A | pay / gateway | src | AES-256-GCM literal | tokenisation | N | C | Int | 7 | KNOWN |
| PAY-004 | A | pay / gateway | keystore | RSA-2048 cert `gateway-p12` | TLS server auth (in-app) | S | C | Int | 7 | KNOWN, keyUsage-derived purpose |
| PAY-005 | A | pay / edge-lb | TLS | ECDSA P-256 cert `pay-edge` | server auth | S | C | Ext | 7 | KNOWN (wire) |
| PAY-006 | A | pay / edge-lb | TLS | ECDHE (P-256/X25519) key exchange | key agreement | S | C | Ext | 7 | KNOWN (wire), groups as offered |
| PAY-007 | A | pay / edge-lb | TLS | AES-128-GCM & AES-256-GCM suites | bulk encryption | G / N | C | Ext | 7 | KNOWN |
| PAY-008 | A | pay / gateway | image/pkg | Bouncy Castle (bcprov) transitive via pom | capability | — | M | Int | — | capability only, no algorithm usage |
| PAY-009 | B | pay / settlement | src+bin | 3DES-CBC (OpenSSL EVP) | file encryption | G* | H | Int | 7 | KNOWN (src), symbol-level in binary |
| PAY-010 | B | pay / settlement | src+bin | RSA-1024 + SHA-1 signing | batch signing | S | H | Int | 7 | KNOWN algorithm, key size UNKNOWN from source (loaded from conf) |
| PAY-011 | C | pay / settlement | HSM | ECDSA P-256 key in SoftHSM2 | signing | S | H | Int | 7 | HSM: NOT_OBSERVED unless PKCS#11 reader built |
| PAY-012 | B | pay / settlement | cert | RSA-1024 `settle-legacy` | signing | S | H | Int | 7 | KNOWN, weak-classical flag |
| INF-001 | A | infra / pki | cert | RSA-4096 root CA, 20 y | CA signing | S | C | Int | 20 | KNOWN |
| INF-002 | B | infra / pki | cert | ECDSA P-384 intermediate | CA signing | S | C | Int | 10 | KNOWN |
| INF-003 | B | infra / pki | cert | SHA-1-signed intermediate | CA signing | S (key) + SHA-1 sig | H | Int | 10 | KNOWN, sig alg flagged |
| INF-004 | B | infra / pki | CRL | revoked ECDSA leaf | server auth | S | M | Int | 1 | lifecycle REVOKED only if CRL parsed; else UNKNOWN |
| INF-005 | B | infra / pki | cert | self-signed dev RSA-2048 | none declared | S | L | Int | 1 | KNOWN, purpose UNKNOWN (no keyUsage) |
| INF-006 | B | infra / pki | keystore | JKS truststore (multiple CA certs) | trust anchors | S | M | Int | — | KNOWN per contained cert |
| INF-007 | C | infra / ssh | config | RSA host key, ssh-rsa (SHA-1) | host auth | S | H | Int | 1 | config evidence or visibility: SSH unsupported |
| INF-008 | C | infra / ssh | config | Ed25519 host key | host auth | S | H | Int | 1 | same |
| INF-009 | C | infra / ssh | config | KEX dh-group14-sha1 | key agreement | S | H | Int | 1 | same |
| INF-010 | C | infra / ssh | config | KEX mlkem768x25519-sha256 | key agreement | P (hybrid) | H | Int | 1 | same; must not be queued for replacement |
| INF-011 | C | infra / ssh | config | hmac-sha1, aes128-ctr | integrity / encryption | — / G | H | Int | 1 | same |
| INF-012 | C | infra / ipsec | config | IKEv2 MODP-2048 + AES-256 + SHA-256 | key agreement / enc | S / N | H | Int | 5 | config evidence or visibility: IPsec unsupported |
| INF-013 | C | infra / ipsec | config | ESP AES-128 + SHA-1 + MODP-1024 | enc / integrity / KA | G / — / S | H | Int | 5 | same |
| INF-014 | C | infra / ipsec | cert | RSA-3072 `ipsec-gw` | peer auth | S | H | Int | 5 | KNOWN (cert file) |
| INF-015 | B | infra / jvm | config | java.security re-enabling legacy algs | policy | — | H | Int | — | config evidence (Directive 4) or visibility entry |
| INF-016 | B | infra / k8s | config | Helm TLS minVersion 1.2 + cipher list | policy | — | H | Int | — | config evidence or visibility entry |
| INF-017 | A | infra / k8s | secret | base64 EC private key (throwaway) | TLS key | S | C | Int | — | finding KNOWN, **material redacted everywhere** |
| INF-018 | B | infra / kms | KMS mock | RSA_4096 SIGN_VERIFY | signing | S | H | Int | 10 | KNOWN (DECLARED-source: mock metadata) |
| INF-019 | B | infra / kms | KMS mock | SYMMETRIC_DEFAULT | envelope encryption | N (VERIFY: AES-256-GCM) | H | Int | 10 | KNOWN |
| INF-020 | B | infra / kms | KMS mock | ECC_NIST_P256 | signing | S | M | Int | 3 | KNOWN |
| INF-021 | B | infra / pqc-edge | TLS | X25519MLKEM768 group | key agreement | P (hybrid) | H | Ext | 7 | KNOWN if sslyze reports it; else CONFLICTING/UNKNOWN — never "X25519 only" silently |
| INF-022 | C | infra / pqc-edge | cert | ML-DSA-65 leaf (optional) | server auth | P | H | Ext | 7 | KNOWN or unsupported-algorithm entry |
| HR-001 | B | hr / portal | src | Fernet (AES-128-CBC + HMAC-SHA256) | record encryption | G | H | Int | 8 | INFERRED from library semantics, never KNOWN from literal |
| HR-002 | B | hr / portal | src | PyJWT RS256 | token signing | S | H | Ext | 1 | KNOWN (literal `algorithm="RS256"`) |
| HR-003 | B | hr / portal | src | bcrypt | password hashing | N (VERIFY framing) | H | Int | 8 | KNOWN |
| HR-004 | B | hr / portal | config+cert | SAML RSA-SHA256, cert expiring | assertion signing | S | H | Ext | 1 | cert KNOWN + EXPIRING; alg from env = INFERRED |
| HR-005 | B | hr / portal | pkg/bin | OpenSSL bundled inside `cryptography` wheel | capability | — | M | Int | — | package KNOWN; embedded OpenSSL KNOWN only if binary adapter inspects wheel `.so` |
| RES-001 | B | research / datalake | src+bin | X25519 ECDH | key agreement | S | H | Int | 25 | src KNOWN; binary: likely UNKNOWN (weak constants) |
| RES-002 | B | research / datalake | src+bin | Ed25519 | signing | S | H | Int | 25 | same |
| RES-003 | B | research / datalake | src+bin | AES-256-GCM | encryption | N | H | Int | 25 | src KNOWN; binary YARA S-box → AES (mode/size UNKNOWN) |
| RES-004 | B | research / datalake | bin | SHA-256 constants | hashing | N | H | Int | 25 | YARA KNOWN (family only) |
| RES-005 | B | research / notebook | src | jsonwebtoken ES256 | token signing | S | M | Ext | 1 | KNOWN |
| CUS-001 | B | customer / portal | src | AES-256-CBC (static IV) | field encryption | N | H | Ext | 8 | KNOWN; misuse not scored |
| CUS-002 | B | customer / portal | cert/TLS | RSA-2048 expired cert | server auth | S | H | Ext | 8 | KNOWN + EXPIRED |
| CUS-003 | B | customer / portal | vendored | node-forge (RSA, AES, 3DES, HMAC, SHA-1…) | capability | — | M | Ext | — | capability; usage only where called; vendored ⇒ no manifest ⇒ package adapter misses it |
| CUS-004 | B | customer / ivr | bin | libcrypto dyn-link; AES-128-GCM + ECDSA symbols | unknown | G / S | M | Int | 8 | symbol-level, confidence low, purpose UNKNOWN |
| CUS-005 | C | customer / statements | src (COBOL) | mainframe symmetric encryption call | statement encryption | UNKNOWN | H | Int | 10 | **visibility: unsupported_language**, no asset |

\* 3DES: effective classical strength already ~112-bit and deprecated by NIST independent of quantum; the harness scores the *classical-deprecation* flag separately from the quantum tier. (FACT: NIST SP 800-131A disallows TDEA for encryption after 2023 — VERIFY exact revision wording.)

### 7.3 Traps & negative controls (`traps.yaml`)

| ID | Location | Content | Correct behaviour |
|---|---|---|---|
| TRAP-01 | `LegacyCardHash.java` | MD5, unreachable class | finding allowed, `reachable: UNKNOWN/false`, not in risk queue as in-use |
| TRAP-02 | `VectorsTest.java` | AES KAT vectors under `src/test` | finding tagged test-scope; excluded from production inventory |
| TRAP-03 | `docs/SECURITY.md` | the words "RSA", "3DES" in prose | **no finding** |
| TRAP-04 | `internal/cache/key.go` | SHA-1 for cache keys | `security_function: false/UNKNOWN`; not a signature/integrity risk |
| TRAP-05 | `package-lock.json` | `crypto-js` listed as devDependency, never imported | capability only, dev scope |
| TRAP-06 | commented-out `Cipher.getInstance("DES")` | comment | **no finding** (Semgrep ignores comments — VERIFY) |
| TRAP-07 | `controls/no-crypto-service/` | zero crypto | zero assets **and** a coverage entry saying it was scanned |
| TRAP-08 | `INF-010`, `INF-021`, `INF-022` | already-PQC assets | not recommended for replacement |
| TRAP-09 | `pay-tls-secret.yaml`, generated `.p12` | real (throwaway) key material | no PEM/key bytes in DB, UI, CBOM, logs |
| TRAP-10 | env var name `AES_KEY_ROTATION_DAYS=90` | string containing "AES" | no algorithm asset |

### 7.4 Relationships (`relationships.yaml`, excerpt)

Each edge carries the expected `evidence_basis` and `epistemic_state` (TOPO-001 / T1; replaces the earlier "provenance" column). `assurance` is shown only for artifact-asserted edges.

| From | Type | To | Expected evidence_basis / epistemic_state |
|---|---|---|---|
| payment-gateway (repo) | declares-dependency | bcprov (PAY-008) | observed / KNOWN (pom content) |
| payment-gateway (repo) | built-into | image `meridian/payment-gateway` | artifact_asserted / DECLARED, assurance per TOPO-07; config_declared / DECLARED if only Dockerfile + build config; no edge if neither |
| image `payment-gateway` | contains | `gateway.p12` (PAY-004) | observed / KNOWN (image layer) |
| edge-lb | terminates-tls-for | payment-gateway | config_declared / DECLARED (`haproxy.cfg` backend) |
| edge-lb endpoint :8443 | presents | `pay-edge` cert (PAY-005) | observed / KNOWN (wire, T7 scope) |
| `pay-edge` | issued-by | `int-ca-ecc` | observed / KNOWN (chain signature verified) |
| `int-ca-ecc` | issued-by | `root-ca` | observed / KNOWN (chain signature verified) |
| KeyWrapService call site | configured-by | `application.yml` key | inferred / INFERRED (CFG-001, rule_id required) |
| settlement-batch | uses-hsm-key | SoftHSM2 `settle-sign` | observed / KNOWN only if a PKCS#11 reader exists; otherwise **no edge** + visibility `HSM: NOT_OBSERVED` |
| hr-portal | depends-on (transitive) | `cryptography` | observed / KNOWN (lock file) |
| `cryptography` | bundles | OpenSSL instance | inferred / INFERRED (rule_id), KNOWN only if the binary adapter inspects the wheel's shared object |
| datalake-sync binary | built-from | `research/datalake-sync` source | human_declared / DECLARED |
| customer-portal | vendors | node-forge | observed / KNOWN (path) — no manifest entry |
| ipsec dc-to-dr | authenticates-with | `ipsec-gw` cert | config_declared / DECLARED (config path reference) |
| **PAY-001 RSA key (source)** | **same-object / shares-public-key** | **PAY-004 RSA key (keystore)** | **MUST NOT EXIST** — different keys; no content identity |
| **PAY-004 (app keystore)** | **serves / presents** | **edge-lb endpoint** | **MUST NOT EXIST** — LB serves a different cert |

The two bold "must-not-exist" edges are the Part 5 over-merge tests. Any ECDAT output containing them scores as a correlation failure regardless of other results.

### 7.5 Declared context & Mosca scenarios

`context.declared.yaml` — one record per application: owner, environment, criticality, data class, X (lifetime). All marked `source: DECLARED`.

`scenarios.mosca.yaml` — Z values are **harness parameters**, deliberately round, not forecasts:

```yaml
scenarios:
  aggressive: { Z_years: 5 }
  central:    { Z_years: 10 }
  optimistic: { Z_years: 15 }
reference_year: 2026            # scoring is relative to this, not wall-clock
```

Expected verdicts (X + Y > Z → "late"):

| Asset | X | Y | X+Y | aggressive (5) | central (10) | optimistic (15) |
|---|---|---|---|---|---|---|
| RES-001 X25519 (research, 25 y) | 25 | 2 | 27 | late | late | late |
| INF-001 root CA | 20 | 4 | 24 | late | late | late |
| PAY-001 RSA-OAEP | 7 | 3 | 10 | late | **boundary (not >)** | ok |
| HR-002 RS256 JWT | 1 | 1 | 2 | ok | ok | ok |
| PAY-009 3DES (Grover) | 7 | 2 | 9 | tier ≠ Shor → Mosca verdict shown but action = "increase key size / replace for classical reasons" | | |

PAY-001 sits exactly on the boundary in the central scenario on purpose: tests that the implementation uses strict `>` as stated in the architecture, and that sensitivity (±5 y on X or Z) flips it visibly.

**Note on signing assets:** HR-002 is a short-lived signature. Mosca's "secrecy lifetime" semantics fit confidentiality far better than signatures (there's nothing to harvest). OPEN QUESTION for the risk engine: should signature assets use a different X (validity/trust horizon) rather than data lifetime? The harness records both values so either design can be scored.

### 7.6 Recommendation oracle (`recommendations.oracle.yaml`)

Directive 6 says outputs are *candidate option sets*, so the oracle is a set of **acceptable** and **unacceptable** options per policy profile, not one right answer.

```yaml
REC-PAY-001:        # RSA-OAEP key transport
  purpose_known_only_if: config_resolved
  profile_default:
    acceptable: [ML-KEM-768, hybrid-X25519+ML-KEM-768 (KEM-based redesign)]
    unacceptable: [ML-DSA-*, RSA-4096]   # signature alg for KEM job; size increase doesn't help Shor
  profile_cnsa2:
    acceptable: [ML-KEM-1024]
  if_purpose_unknown: "insufficient evidence for purpose-specific recommendation"
REC-INF-001:        # root CA, long-lived
  acceptable: [SLH-DSA, LMS/XMSS (policy-dependent), ML-DSA-87]
REC-PAY-009:        # 3DES
  acceptable: [AES-256-GCM]
  unacceptable: [any PQC KEM/signature]  # wrong category
REC-INF-021:        # already hybrid
  acceptable: [no-action]
```

(Algorithm choices reflect Part 8 of the architecture; FIPS status per that document's verified table. VERIFY FIPS 206 / HQC status again before finals.)

### 7.7 Expected visibility (`visibility.expected.yaml`, excerpt)

| Dimension | Expected entry (MVP adapters) |
|---|---|
| source coverage | Java/Python/Go/TS/C scanned; COBOL `STMTENC.cbl` → unsupported_language |
| configuration visibility | application.yml, .env, Helm, java.security, sshd_config, swanctl.conf → resolved OR explicitly listed as unresolved |
| dependency coverage | vendored `node-forge` → not in any manifest (must be listed as found-by-path or missed) |
| binary coverage | datalake-sync: stripped static → symbol analysis N/A, YARA only |
| runtime visibility | NOT_OBSERVED (no runtime sensor) |
| network visibility | edge-lb, customer-portal, pqc-edge probed; bastion SSH → unsupported protocol |
| HSM/KMS visibility | KMS: mock parsed; HSM: NOT_OBSERVED unless PKCS#11 reader |
| failed/timeout | one deliberately hung TCP endpoint (`tarpit:9443`) → timeout entry |

Add `tarpit` — a container that accepts TCP and never speaks TLS — to test per-target timeouts (Part 1).

### 7.8 Temporal delta (`deltas/v1_to_v2.yaml`)

`v2` changes, each an expected delta:
- `pay-edge` reissued (new serial, same algorithm) → certificate change, no risk change
- `PAY-010` RSA-1024 removed → asset removed
- new file in hr-portal using `ECDSA P-256` → newly introduced Shor-broken asset
- `INF-009` dh-group14-sha1 removed from sshd_config → migration progress
- `edge-lb` group list gains X25519MLKEM768 → migration progress

---

## 8. Testing strategy

### 8.1 Two scoring layers

1. **Against planted truth** → recall/precision. Upper bound only (circularity, Section 0).
2. **Against expected observation** → *honesty*. This is the metric that matters for the trust thesis.

### 8.2 Metrics

| Capability | Metric | Notes |
|---|---|---|
| Discovery | Finding-level precision & recall **per surface** | Never one global number (Directive 3) |
| Asset resolution | Asset-level P/R after within-surface merge; **over-merge count** (must be 0) | Bold edges in 7.4 |
| Classification | Exact-match rate on family, parameters, primitive, crypto function, quantum tier | Score parameters only where planted truth says observable |
| Purpose | Accuracy **including UNKNOWN as a correct answer** | Forced guess = wrong even if it happens to be right |
| **False-certainty rate** | # fields reported KNOWN where expected state ∈ {UNKNOWN, INFERRED, DECLARED} ÷ total such fields | **Target: 0.** Headline trust metric |
| Under-claiming rate | # fields reported UNKNOWN where expected KNOWN | Tolerable, but tracked — an all-UNKNOWN tool is useless |
| Relationships | Edge P/R split by `evidence_basis`; accuracy of `evidence_basis`, `epistemic_state`, `assurance` labels | Any label mismatch counts as an error; forbidden edges are hard failures |
| Trap handling | # traps producing forbidden output | Target 0 |
| Visibility | Recall of expected visibility entries | Missing blind-spot entry = failure |
| CBOM | Schema-valid against canonical CycloneDX 1.6 JSON schema; undetermined bucket present; zero secret bytes | Hard gate, pass/fail |
| Quantum tier | Exact match | Deterministic — anything below 100% is a bug |
| Mosca | Golden-output match per scenario; boundary case uses strict `>` | Tests determinism, not "accuracy" |
| Sensitivity | Property test: increasing X or decreasing Z never *improves* an asset's verdict | Monotonicity |
| Recommendations | % in acceptable set; # in unacceptable set (target 0); purpose-UNKNOWN → insufficient-evidence (100%) | |
| Temporal | Delta P/R vs `v1_to_v2.yaml` | |
| Security of ECDAT | grep DB dump, CBOM, UI HTML, logs for `-----BEGIN`, base64 key blobs, known throwaway key fingerprints | Pass/fail |
| Performance | Wall time per target; timeout honoured on `tarpit` | Budget per Part 14 abort signals (~2–3 min/scanner on demo data) |

### 8.3 Tool-behaviour experiments (test before believing)

Run these **before** writing adapters, because they decide adapter design:

| Experiment | Question | Outcome feeds |
|---|---|---|
| E1 | Does Trivy extract Go module info from a `-s -w` static binary in a `scratch` image? | Whether RES-* get package evidence |
| E2 | YARA crypto-constant rules on `datalake-sync`: which of AES/SHA-256/X25519/Ed25519 fire? | Binary expected-observation column |
| E3 | Does sslyze report `X25519MLKEM768` as a group? If not, what does it say? | INF-021 expectation; possible fallback to testssl.sh / openssl s_client |
| E4 | Can OpenSSL 3.x (your base image) issue SHA-1-signed and RSA-1024 certs and serve them over TLS at the default seclevel? | Whether INF-003/PAY-012 need seclevel overrides |
| E5 | Semgrep: C support level on `settle.c`; confirm comments ignored; confirm no COBOL | Source coverage matrix |
| E6 | Does any scanner see the OpenSSL bundled inside the `cryptography` wheel? | HR-005 expectation |
| E7 | Keystore parsing of PKCS12 and JKS with the chosen library | PAY-004, INF-006 |

Record results in `harness/eval/experiments.md` with tool versions. Tool versions are pinned; re-run on upgrade.

### 8.4 Blind holdout

A teammate who **does not write rules** plants 8–12 assets in `holdout/` using the same schema, without telling the rule authors what they planted. Scores on the holdout are the most honest internal numbers you'll have. Seal the holdout ground truth until after a rule-freeze.

### 8.5 External validation (the part that actually earns credibility)

Per architecture Part 12:
1. Pick 2 real open-source targets (one JVM application, one public container image) small enough to enumerate by hand in a few days. Pick them **before** tuning rules.
2. Manually enumerate crypto; write ground truth in the *same schema*.
3. Run the **same frozen ECDAT build** — no config change, no rule change.
4. Dogfood: run ECDAT on ECDAT.
5. Report harness numbers and external numbers **side by side**. Expect external recall to be lower. That gap is the honest answer to "how good is it really?"

### 8.6 Anti-overfitting controls

- **Rule freeze hash:** the rule set (Semgrep YAML, YARA, parsers config) is hashed; every scoring run records the hash. External runs must match the harness-run hash.
- **Identifier grep in CI:** fail the build if scanner code/rules contain `meridian`, `ecdat-harness`, any `targets/` path segment, or harness hostnames.
- **Mutation test:** `mutate.py` renames directories, files, Java packages, variable names and hostnames, shuffles file order, and moves the config key to a different yml path. Scores on mutated harness must equal unmutated scores (except for things that legitimately depend on names — none should). A drop means the scanner is keying on harness specifics.
- **No harness-conditional code paths.** The scanner takes a target and a scan config. Nothing else.

### 8.7 Regression

Every ECDAT change runs: Tier A (fast, <5 min target) on every commit; Tiers B+C nightly or before demos. Score diffs are reviewed like test failures.

---

## 9. Safety of the harness itself

- All keys are throwaway, generated per build, marked `TEST-ONLY — Meridian harness` in the subject CN/O. Never reuse outside the harness.
- `targets/**/keystore/`, `targets/infrastructure/pki/`, `pki-lock.generated.json` are gitignored.
- Docker network is `internal: true`; no egress. TLS/SSH probing is only authorised against harness containers, and the scan request must carry the allow-list + consent flag (Part 1) even in the harness — test that probing a non-listed host is refused.
- The KMS inventory is a static mock. No cloud credentials anywhere in the harness.
- Treat ECDAT output from harness runs as test data, but still run the redaction checks — the point is to prove the controls work.

---

## 10. What this harness deliberately does NOT do

| Not built | Why |
|---|---|
| Live IPsec tunnels | Needs privileged containers; config evidence tests the same parsing |
| Real cloud KMS / real HSM | Credentials and cost; mock + SoftHSM2 exercise the parsers |
| Real mainframe / COBOL execution | Only the "unsupported language" visibility behaviour is tested |
| Runtime instrumentation fixtures | No runtime sensor in MVP (Part 13) |
| Crypto-misuse scoring | Different problem (misuse ≠ inventory); recorded as notes only |
| Thousands of repos for scale | Premature. Add a "×N vendored copies" generator only once a scanner is shown to be the bottleneck |
| Enterprise dollar-cost oracle | Directive 7 — migration *impact*, not cost |
| An "accuracy %" slide from harness data alone | Circular (Section 0) |

---

## 11. Open questions (need a decision, not assumed here)

1. ~~Config-chain resolution — MVP or not?~~ **Closed → CFG-001 (FROZEN), Section 14.** It was never optional: Directive 4 mandates configuration evidence. Only depth was open.
2. **SSH/IPsec: config parsers or visibility-only?** Cheap config parsers would close a problem-statement gap ("protocols"); visibility-only is the honest minimum.
3. **PKCS#11 metadata reader** — build (converts HSM from NOT_OBSERVED to covered) or defer?
4. **Mosca X for signature assets** — data lifetime vs trust horizon (Section 7.5).
5. **Library-semantics inference (Fernet → AES-128-CBC)** — is a curated semantics table an acceptable INFERRED source, and who maintains it?
6. **Dead-code / test-scope detection** — heuristic path-based tagging, or leave `reachable: UNKNOWN`?

---

## 12. Verification checklist before building

| Item | Status |
|---|---|
| CycloneDX 1.6 enum values used in the manifest | VERIFY against canonical schema |
| OpenSSL 3.5 ML-KEM/ML-DSA + hybrid group; nginx build against it | VERIFY |
| OpenSSH version for `mlkem768x25519-sha256` | VERIFY (believed ≥ 9.9) |
| sslyze hybrid-group reporting | TEST (E3) |
| Trivy on stripped static Go | TEST (E1) |
| Semgrep C support level; no COBOL | VERIFY + TEST (E5) |
| `cryptography` wheels bundle OpenSSL statically | VERIFY + TEST (E6) |
| AWS KMS `DescribeKey` field names/key specs for the mock | VERIFY against AWS docs |
| ICSF callable-service names for the COBOL file | VERIFY |
| NIST SP 800-131A TDEA status wording | VERIFY |
| Fernet = AES-128-CBC + HMAC-SHA256 | FACT (Fernet spec) |
| OpenSSL 3 seclevel behaviour for SHA-1/RSA-1024 on your base image | TEST (E4) |

---

## 13. Highest-ROI next steps

1. Run experiments **E1–E4** (half a day). They change the expected-observation table more than anything else in this document.
2. Build **Tier A only**: payment-gateway + edge-lb + PKI + one trap + no-crypto control, with ground truth for PAY-001…008, INF-001, INF-017, TRAP-01/03/07/09.
3. Write `score.py` with the false-certainty metric first — it's the metric that operationalises the product thesis.
4. Pick the two external OSS targets now, before rules exist.
5. Only then expand to Tier B.


---

## 14. Decision ledger

### CFG-001 — Narrow static configuration-chain resolution

| Field | Content |
|---|---|
| **ISSUE** | Tier A's headline case (PAY-001) depended on an undecided feature. |
| **STATUS** | **FROZEN** incl. A1–A5 and W1–W2 (accepted 2026-09-16). |
| **VERIFIED FACTS** | Spring Boot docs (reference, 4.1.1): property-source order places config data (`application.*`) at position 3, OS environment variables at 5, Java system properties at 6, `SPRING_APPLICATION_JSON` at 10, command-line args at 11; later sources override earlier ones. Profile-specific files override non-specific ones; multiple active profiles are last-wins. `spring.config.import`-ed values override the importing file. Env vars bind via uppercase/underscore relaxed binding (`PAY_KEYWRAP_TRANSFORMATION` → `pay.keywrap.transformation`). |
| **UNVERIFIED CLAIMS** | None load-bearing. JCE type constraint in A3 is ENGINEERING INFERENCE (`WRAP_MODE` with a `PublicKey` requires an asymmetric transformation) — confirm by running the fixture. |
| **ASSUMPTIONS** | The harness app has no `EnvironmentPostProcessor`, custom `PropertySource`, or `setEnvironmentPrefix` (each silently changes resolution). |
| **OPTIONS** | (A) no config resolution — **rejected: contradicts Directive 4**. (A-narrow) one pattern, INFERRED only — **chosen**. (A-full) reproduce Spring's config engine — **rejected: disproportionate complexity, still not runtime truth**. |
| **DECISION** | MVP resolves: crypto API → known property binding (`@ConfigurationProperties` / `@Value`) → literal in same-repo `application.yml`/`.yaml`. Successful resolution is **INFERRED, never KNOWN**. Full evidence chain preserved. Deployment-level overrides represented only when explicitly present in scanned deployment config; effective value INFERRED from documented precedence. Unsupported paths produce explicit unresolved state + reason. **"Effective" ≠ "observed"**: runtime state is always `NOT_OBSERVED` absent a runtime sensor. |
| **OUT OF SCOPE** | external config systems (Consul, Vault, cloud secret managers, Spring Cloud Config); runtime config retrieval; cross-repo config; profile resolution without a known active profile; `spring.config.import` / `spring.config.location`; JNDI; reflection/dynamic property names; custom property sources; Helm rendering (see A2). |
| **REJECTED** | Labelling any two-valued situation CONFLICTING (the user's refinement, accepted): two values with an established precedence is an *override*, not a conflict. |
| **EVIDENCE** | Spring Boot reference, "Externalized Configuration" (docs.spring.io/spring-boot/reference/features/external-config.html), fetched 2026-09-16. Directive 2, Directive 4. |
| **IMPACT** | Evidence model gains `ConfigurationCandidate` and `EffectiveConfigurationInference` (below). PAY-001 fixture becomes a 7-state matrix (14.3). HR-004 (`.env`) is out of CFG-001's Spring scope → UNRESOLVED(reason: non-Spring config binding). |

#### Amendments A1–A5 (FROZEN)

**A1 — "Effective" is only effective among the sources inspected.** Env vars (5) are *not* the top of the stack. Command-line args (11), `SPRING_APPLICATION_JSON` (10) and `-D` system properties (6, commonly injected via `JAVA_TOOL_OPTIONS`) all beat them, and all three can sit in the same Kubernetes manifest ECDAT is already reading. So the output must carry `higher_precedence_sources_inspected` and `…_not_inspected`. v1 does not *resolve* those sources, but must **detect** a literal occurrence of the property key in container `args`/`command`, `JAVA_TOOL_OPTIONS`, or `SPRING_APPLICATION_JSON` in the same manifest — a string match, not a parser — and if found, degrade to UNRESOLVED(reason: higher-precedence source present, unsupported). Claiming the env value is effective while a `--pay.keywrap.transformation=` arg sits two lines below it is false certainty.

**A2 — A Helm `values.yaml` is not deployment configuration.** A value in `values.yaml` does nothing unless a template renders it, and environment-specific values files / `--set` flags are usually invisible. v1 reads **plain Kubernetes manifests** (literal `env[].value`) only. An unrendered Helm chart yields UNRESOLVED(reason: unrendered Helm chart; values overrides unknown). Rendering with chart defaults (`helm template`) is a candidate v1.1, and even then must carry "values overrides not observed." `env[].valueFrom` (secretKeyRef / configMapKeyRef) → UNRESOLVED(reason: indirect env source).

**A3 — Planted override values must be runtime-valid.** An override of `ECDSA` (as in the user's example) would make `Cipher.getInstance` throw — the harness would be planting an impossible deployment. The code wraps with a `PublicKey`, so the override must be an asymmetric transformation. Use `RSA/ECB/PKCS1Padding`: same family and quantum tier (Shor), different padding (legacy PKCS#1 v1.5). This also creates a useful property: in the CONFLICTING state, *family, primitive, purpose and quantum tier agree across all candidates* while padding does not.

**A4 — Epistemic state vs resolution status are different fields.** Directive 2's state set has no UNRESOLVED. Do not add one silently. Model as `epistemic_state ∈ {KNOWN, UNKNOWN, NOT_OBSERVED, NOT_APPLICABLE, INFERRED, DECLARED, CONFLICTING}` **plus** `resolution_status ∈ {RESOLVED, OVERRIDDEN, UNRESOLVED}` with `reason`. States are assigned **per field** (family, padding, purpose…), not per asset — which is what makes A3's partial agreement expressible, and lets the risk engine assign the Shor tier even when the exact transformation is CONFLICTING.

**A5 — A manifest override only applies if the manifest provably runs this application.** State C silently assumes the Deployment belongs to payment-gateway. v1 attaches an override only when the manifest's container `image` matches an image name declared by the same repository's build config. Otherwise: record the override as an unattached candidate, reason "deployment-to-application link unresolved". This is the entry point to the next issue (topology layer).

### 14.2 Evidence-model additions (conceptual, not schema)

```
ConfigurationCandidate
  property_key            pay.keywrap.transformation
  value                   RSA/ECB/OAEPWithSHA-256AndMGF1Padding
  source_kind             spring-config-data | os-env | cli-arg | system-prop | spring-app-json
  source_location         file:path:line
  precedence_rank         per Spring reference order
  applicability           APPLICABLE | CONDITIONAL(profile=prod) | UNKNOWN

EffectiveConfigurationInference
  property_key
  winning_candidate       -> ConfigurationCandidate
  losing_candidates       [ ... ]
  rule_applied            "Spring Boot property-source order"
  sources_inspected       [ ... ]
  higher_precedence_not_inspected [ ... ]      (A1)
  epistemic_state         INFERRED | CONFLICTING | UNKNOWN
  resolution_status       RESOLVED | OVERRIDDEN | UNRESOLVED(reason)
  runtime_observation     NOT_OBSERVED
```

### 14.3 PAY-001 state matrix (one fixture variant per state)

Each state is a separate small fixture overlay (`targets/payments/payment-gateway/` + overlay dir applied at harness build), so all states are regression-tested, not just the one in the default tree.

| State | Planted inputs | Expected: transformation | Other expected fields |
|---|---|---|---|
| **A** | source only (no yml value) | UNKNOWN; UNRESOLVED(no binding value found) | finding KNOWN (dynamic call site); purpose INFERRED key-transport from `WRAP_MODE`* |
| **B** | + `application.yml` = OAEP | INFERRED `RSA-OAEP-SHA256`; RESOLVED | higher-precedence inspected: none present in scanned manifests; runtime NOT_OBSERVED |
| **C** | B + k8s Deployment (image matches, A5) `env PAY_KEYWRAP_TRANSFORMATION=RSA/ECB/PKCS1Padding` | INFERRED `RSA-PKCS1v1.5`; OVERRIDDEN | yml value kept as losing candidate; warning "effective value depends on deployment config" |
| **D** | B + `application-prod.yml` = PKCS1; no known active profile; no env override | **CONFLICTING** {OAEP, PKCS1} | family/primitive/purpose/quantum tier INFERRED (all candidates agree); padding CONFLICTING |
| **E** | D + state-C env override | same as C | profile uncertainty irrelevant for this key: env (5) outranks all config data (3) — verified order |
| **F** | B + Deployment also has `args: ["--pay.keywrap.transformation=RSA/ECB/PKCS1Padding"]` | UNKNOWN; UNRESOLVED(higher-precedence source present, unsupported) | **must not** report B's or C's value as effective (A1) |
| **G** | B + Helm `values.yaml` containing the env entry under a key **no template references** | same as B (or UNRESOLVED(unrendered Helm) per A2) | **must not** report OVERRIDDEN |

\* Whether `WRAP_MODE` → key-transport is an acceptable source-level purpose inference remains an open rule-design question; score it as INFERRED-or-UNKNOWN (both accepted), never KNOWN.

Scoring: any state where the transformation is reported KNOWN, or where F/G report an override value as effective, is a false-certainty failure.

### 14.4 Tests required before implementing the adapter

1. Build and run the real payment-gateway fixture for states B, C, D(with `SPRING_PROFILES_ACTIVE=prod`), F — hit an actuator `/env` or log the bound value — to confirm the *actual* runtime winner matches the expected column. The harness answer key must itself be validated against the runtime, not against the docs.
2. Confirm `Cipher.getInstance("RSA/ECB/PKCS1Padding")` + `WRAP_MODE` with the planted `PublicKey` works on the pinned JDK (A3).
3. Confirm the state-D fixture fails over to state E behaviour when the env var is added (precedence sanity).

### 14.6 Wording fixes W1–W2 (FROZEN)

**W1 — "any uninspected higher-precedence source → UNKNOWN" collapses every result.** Some sources are unobservable by nature (runtime `kubectl patch`, admission webhooks, operator-injected env, `-D` flags added by a launcher). If their mere possibility forces UNKNOWN, state B can never be INFERRED. Rule instead:
- source **present in scanned material but unsupported/unparseable** (shell-form `sh -c "java $JAVA_OPTS ..."`, unrendered Helm, `valueFrom`) → UNRESOLVED;
- source **not visible to static scanning at all** → listed in `higher_precedence_not_inspected`, INFERRED retained.

Resolution of the four deployment sources is limited to **literal exec-form** values (`args: ["--k=v"]`, literal `-Dk=v` in `JAVA_TOOL_OPTIONS`, literal JSON). Also add to the inspected/not-inspected list: image `ENTRYPOINT`/`CMD` (Dockerfile) and **ConfigMap-mounted external `application.yml`** (config data outside the jar overrides the packaged file — lower than env, higher than the repo yml). New trap **H**: B + ConfigMap volume mounting `/config/application.yml` with PKCS1 → expected OVERRIDDEN/INFERRED if the ConfigMap is in the same repo, else UNRESOLVED.

**W2 — no "DERIVED" epistemic state.** A4 forbids extending the vocabulary silently. A rule-derived field (quantum tier from family) takes the **weakest epistemic state of its inputs** and records `derived_from` + `rule_id` as derivation metadata. Family inferred from config ⇒ tier INFERRED, not KNOWN, not DERIVED.

### 14.5 Foundational rules extracted from CFG-001

- **R-UNSEEN:** a merely possible unseen source does not invalidate an inference; an identified, relevant source that is present but unsupported does.
- **R-DERIVE:** a derived field cannot be more certain than its weakest required input; derivation is recorded as `derived_from` + `rule_id`, never as a new epistemic state.
- **R-MONOTONE:** adding stronger evidence may reduce uncertainty but must never create certainty the evidence does not support (PAY-001 D→E).


---

## 15. TOPO-001 — Topology / evidence correlation

**STATUS:** FROZEN (2026-09-16) incl. T1–T7.

### 15.1 Frozen core

- ECDAT does not discover enterprise topology. It correlates **declared topology** with **independent observations** using explicit rules, and reports supported relationships and contradictions.
- Relationship `evidence_basis` ∈ {observed, content_identity, artifact_asserted, config_declared, human_declared, inferred}. These are evidence bases, **not** strength levels and **not** epistemic states.
- Cross-surface merging remains prohibited except via provable content identity. `same-object` never implies `serves`, `deployed-on`, `owned-by`.
- Conflict detection is **enumerated**, each conflict names its rule. No generic graph inference engine.
- Ownership staleness is never inferred without technical evidence.

**Verified inputs:** OCI image-spec defines `org.opencontainers.image.source` / `.revision` as annotation metadata (claims, not proof). Docker docs: BuildKit adds min-mode provenance attestations by default. SLSA: provenance trust depends on signing/build-platform protections. SSLyze 6.x scans a server's TLS config and serialises to JSON.

### 15.2 Amendments T1–T6 (FROZEN)

**T1 — Collapse the relationship fields.** The accepted text currently mixes `provenance: DISCOVERED`, `evidence_basis`, `epistemic_state`, `assurance`, and numeric `confidence` — and the final schema dropped `assurance`. Single contract:

```
Relationship
  type, source_entity, target_entity
  evidence_basis      observed | content_identity | artifact_asserted | config_declared | human_declared | inferred
  assurance           (artifact_asserted only) unsigned_annotation | unsigned_attestation | signature_verified
  epistemic_state     Directive-2 set
  rule_id             required for inferred, content_identity, and every conflict
  evidence_refs[]     each ref carries its own Part-3 confidence; the edge has NO free-standing numeric confidence
  observed_at
```
Directive 5's "discovered / inferred / declared status" is satisfied by `evidence_basis` + `epistemic_state`; no separate `provenance` field.

**T2 — C1 must key on termination, not "behind".** A layer-4 / TLS-passthrough load balancer puts the *application's* certificate on the wire legitimately. Rule TLS-FRONT-001 fires only when the declared relation is `terminates-tls-for`, the probe used the **same hostname/SNI** as the declaration, and the edge-lb's own listener certificate was also observed (so "expected cert" is evidence, not assumption). New trap: `ivr-connector` declared *behind* edge-lb in `mode tcp` → **no conflict**.

**T3 — C2 as written is not observable in MVP.** "Observed running image digest" needs cluster/runtime API access, which Part 13 defers. A manifest usually references a mutable **tag**; tag→digest drift in a registry is normal, not a contradiction. Replace with a statically observable rule:
- **IMG-SRC-001:** declared source repository for application A ≠ artifact-asserted `image.source` on the image declared for A. Output names both claims; neither is treated as ground truth.
- Running-digest comparison → deferred until a runtime/cluster-read sensor exists.

**T4 — C3 as written is unrealistic.** CMDBs rarely declare "no crypto", and the check also presupposes attribution (A5): an unattributed certificate is UNATTRIBUTED, not a conflict. Replace with the realistic declared artefact — security attestations in GRC/app registers:
- **TLS-POLICY-001:** declared minimum TLS version / declared cipher policy for an endpoint vs observed handshake capabilities at that endpoint.

**T5 — "SHADOW" is a judgment, "UNATTRIBUTED" is a fact.** Observed evidence with no attachment path is `UNATTRIBUTED`. Calling it shadow IT presumes the CMDB export is complete. The scan request must state declared-inventory scope (e.g. `cmdb_scope: [payments, research]`); evidence outside that scope is `OUT_OF_DECLARED_SCOPE`, not unattributed.

**T6 — Define content identity precisely.**
- Certificates: SHA-256 over **DER** (PEM/DER/PKCS12 encodings canonicalised first) → `same-object`.
- Public keys: SHA-256 over **SubjectPublicKeyInfo DER** → `shares-public-key` (a distinct relation: renewal without rekey, or one key in several certs — security-relevant key reuse).
- Never on private-key material (redaction rule).

**Frozen qualifier on T6:** a DER-hash match proves canonical byte identity only (`rule_id = IDENTITY-CERT-DER-001`). It does not prove genuineness, trust, deployment or association. **R-DERIVE is generalised** to cover edges: a relationship is never stronger than the evidence that establishes it (one rule, not two).

**T7 (FROZEN) — scope lives on entities; rules check compatibility.**
- **Identity ≠ observation context.** Probe-target identity = what ECDAT *asked for*: `{requested host, port, SNI sent, probe_vantage}`. Observation context = what it *got*: `{resolved IP, observed_at, …}`. Resolved IP is context, not identity (DNS round-robin, anycast, LB pools); `observed_at` is never identity.
- Original wording, superseded: endpoint identity = `{hostname, port, SNI sent, resolved IP, probe_vantage, observed_at}`. `probe_vantage` is required because split-horizon DNS makes one hostname resolve to different systems from different networks.
- `environment` / `namespace` are usually **declared**, so they carry their own `evidence_basis` + `epistemic_state` like any other field.
- Every correlation rule declares which scope fields must match. An edge whose required scope fields are UNKNOWN is not created; the case is reported as unresolved correlation.

### 15.3 Harness additions

```
targets/declared/cmdb-export.csv          # human_declared, with planted errors
targets/declared/grc-attestations.yaml    # declared TLS policies (TLS-POLICY-001)
targets/build/                            # CI files; images built with and without annotations/attestations
ground-truth/topology.yaml                # true application graph
ground-truth/conflicts.expected.yaml
```

| Case | Planted | Expected |
|---|---|---|
| TOPO-01 | CMDB: customer-portal `terminates-tls-for` by edge-lb; wire (same SNI) shows portal's own expired cert; edge-lb cert also observed | CONFLICTING, rule TLS-FRONT-001 |
| TOPO-02 | ivr-connector behind edge-lb in `mode tcp` | no conflict |
| TOPO-03 | datalake-sync not in CMDB, research domain in `cmdb_scope` | UNATTRIBUTED |
| TOPO-04 | notebook-gateway not in CMDB, domain outside `cmdb_scope` | OUT_OF_DECLARED_SCOPE |
| TOPO-05 | stale owner, nothing technical contradicts | **no finding** |
| TOPO-06 | CMDB says payment-gateway source = `repo-old`; image annotation says `repo-new` | CONFLICTING, rule IMG-SRC-001 |
| TOPO-07 | same image built three ways: no annotation / annotation only / signed attestation | same edge, assurance = none / unsigned_annotation / signature_verified |
| TOPO-08 | `pay-edge` cert as PEM in repo and on the wire | `same-object` (DER hash); **no** `serves` edge created from it |
| TOPO-09 | `hr-saml-sign` renewed without rekey (two certs, one key) | `shares-public-key` |
| TOPO-10 | GRC says edge-lb minimum TLS 1.3; wire accepts TLS 1.2 | CONFLICTING, rule TLS-POLICY-001 |

### 15.4 Tests before implementing

1. SSLyze fixture: confirm how the SNI/server name used is recorded in JSON output, and behaviour against an SNI-routed HAProxy (TOPO-01/02 depend on it).
2. VERIFY: whether BuildKit provenance attestations survive with the classic docker image store vs only when pushed to a registry / containerd store (TOPO-07 depends on it).
3. Confirm certificate DER canonicalisation yields identical hashes across PEM, DER and PKCS12 extraction.


---

## 16. PRV-001 — Execution layer / provider / legacy (LOCKED-PENDING-EVIDENCE; gate 16.3)

**CURRENT ISSUE:** cryptography is often implemented beneath the application language (JCA providers, OpenSSL providers, OS crypto policy, PKCS#11/HSM, CNG, mainframe services). What minimal evidence model captures that boundary honestly?

**OUT OF SCOPE THIS ROUND:** per-language semantic analysers, runtime instrumentation, mainframe access, Windows registry scanning, FIPS certification judgements.

**Framing correction (to attack):** provider indirection mostly changes *where and how* an algorithm is implemented, not *which* explicitly named algorithm runs. It therefore matters mainly for: key location (HSM-bound, non-exportable), migration feasibility (does the provider/HSM firmware support ML-KEM/ML-DSA?), validation constraints (FIPS mode), and **defaults for under-specified requests** (`Cipher.getInstance("AES")`, default key sizes). It rarely changes the quantum tier of an explicitly named algorithm.

**Options:** O1 ignore providers (rejected: reports "software RSA" for HSM keys); **O2 provider-boundary evidence + narrow resolution (candidate)**; O3 full platform model (overengineering).

**O2 sketch:** call sites carry `dispatch_mode ∈ {explicit_provider, default_provider_chain, platform_service, bundled_library, language_native, unknown}`; provider configuration is resolved with the **same contract as CFG-001** (inspected / not inspected / unsupported, R-UNSEEN) against a per-platform precedence table, initially only: JCA (`java.security` in the image's JDK, `-Djava.security.properties` via CFG-001 sources, source-level `Security.insertProviderAt`, SunPKCS11 config) and OpenSSL 3 (`openssl.cnf` provider activation, `OPENSSL_CONF`). Everything else is recorded as evidence, unresolved. Language adapters declare a support level (full / partial / detect-only / unsupported) that feeds the visibility matrix.

**Tests required before deciding:** JCA provider-order swap with SoftHSM2 (read `Cipher.getProvider()` at runtime); default RSA key size on the pinned JDK; OpenSSL `list -providers` under two configs; crypto-policies behaviour on a Fedora host.


### 16.1 Attack round 1 results (2026-09-16)

**Framing — accepted with a correction.** "Explicitly named ⇒ fully specified" is false. VERIFIED: `RSA/ECB/OAEPWithSHA-256AndMGF1Padding` fixes the OAEP label hash but not the MGF1 digest — SunJCE uses SHA-1 for MGF1 when no `OAEPParameterSpec` is supplied, Bouncy Castle and Conscrypt use SHA-256 (bc-java issue #1033; Conscrypt implementation notes; Android crypto docs). Consequences:
- Provider choice changes effective parameters **even for a transformation string that looks explicit**. Tier unaffected here (RSA → Shor either way), but parameter fields, interoperability and migration notes are affected.
- A transformation string is "fully specified" only if a per-platform rule says so. `explicitness` becomes a per-field property, not a per-call property.
- The PAY-001 planted truth was wrong (claimed MGF1-SHA-256) and is corrected above.

**Where defaults can actually change tier.** Not `Cipher.getInstance("AES")`: mode/padding default (ECB) is a misuse issue, and AES key length comes from the key object, not the cipher. Tier-relevant defaults live in **key generation without explicit size** (`KeyGenerator.getInstance("AES")` without `init`: AES-128 → Grover tier vs AES-256 → not affected). JDK default key sizes are version-dependent — VERIFY on the pinned JDK before relying on any value.

**insertProviderAt — consistency with CFG-001.** Source-level `Security.insertProviderAt(p, 1)` gives a candidate whose *precedence* is known but whose *applicability* (execution) is unknown. CFG-001 state D treats that shape as CONFLICTING with a candidate set, not INFERRED-of-one. Same rule here: provider = CONFLICTING {java.security top provider, p} unless (a) the insertion is in an unconditional startup path under a declared rule, or (b) p does not implement the requested service (then the candidate drops out). "POSSIBLY" is not a state.

**OpenSSL — the real pressure point is instance → config binding, not provider activation.**
- VERIFIED: Node.js (≥ 18.5) reads the `nodejs_conf` section, not `openssl_conf`, unless `--openssl-shared-config`; default config location depends on how OpenSSL is linked. A system `openssl.cnf` activating FIPS under `openssl_conf` does not govern Node's bundled OpenSSL by default.
- Different bundled or vendor OpenSSL instances may have their own compiled configuration paths and build-time defaults (examples to verify per artifact: Python `cryptography` wheels, Node, vendor binaries). Whether a Go program uses OpenSSL at all depends on how it was built; it is not assumed. ECDAT must establish the actual library instance before correlating configuration.
- Rule: a call site may be linked to an OpenSSL provider config only when ECDAT has evidence of **which OpenSSL instance** the call site uses **and** which config file/section that instance reads. Otherwise: provider config recorded, link UNRESOLVED(reason: library-instance-to-config binding unknown).

**Edge naming.** `dispatches-through` asserts an execution path. Use `governed-by-provider-config` with `epistemic_state` and explicit applicability; never "executed via".

**ROI scope cut (proposed).** Provider correlation pays off in MVP only where it changes a decision: (1) **key location** (SunPKCS11 / PKCS#11 config present ⇒ migration constraint), (2) **PQC availability** of the governing provider, (3) **tier-relevant defaults** in key generation. Everything else is recorded, not correlated.

**Revised tests.**
1. OAEP pair: same transformation string under SunJCE and BC; confirm MGF1 digest differs and decryption fails across them.
2. Key-generation defaults: `KeyGenerator("AES")` / `KeyPairGenerator("RSA"|"EC")` without init on the pinned JDK.
3. Node bundled OpenSSL vs a system `openssl.cnf` activating a non-default provider under `openssl_conf`: confirm Node ignores it by default.
4. `insertProviderAt` in a conditional branch vs static initializer: expected CONFLICTING vs rule-dependent.
5. Fedora crypto-policies (unchanged).


### 16.2 Accepted decisions (2026-09-16)

| Decision | Result |
|---|---|
| Explicitness evaluated per field, not per call-site string | ACCEPTED |
| Source-level `insertProviderAt` → CONFLICTING candidate set (two narrow exceptions) | ACCEPTED |
| OpenSSL call site linked to provider config only after instance identity **and** instance→config binding are evidenced | ACCEPTED (mandatory) |
| Edge name `governed-by-provider-config` (with epistemic_state, applicability, rule_id) | ACCEPTED |
| Provider correlation enters decisions only for: key location; migration-option availability; tier-relevant generation defaults | ACCEPTED (hard constraint) |
| Provider capability counts only if it constrains migration options **for this asset's operation/purpose/parameter set** (ML-DSA support is irrelevant to an RSA-OAEP key-transport asset) | ACCEPTED |

**Clarifications recorded with the freeze text:**
- **No DERIVED state (W2 restated).** Illustrative outputs must use Directive-2 states only. A rule-derived tier inherits the weakest required input (R-DERIVE). In PAY-001 the family comes from the config chain, so family = INFERRED and tier = INFERRED, with `derived_from`/`rule_id` as derivation metadata. Tier stays determinable while `mgf1_hash` is UNKNOWN because no rule makes tier depend on MGF1.
- **Migration-option availability is mostly UNKNOWN for HSMs in MVP.** A PKCS#11 token's supported mechanisms come from a live `C_GetMechanismList` call on the token, not from static config. Static evidence usually shows *that* keys live in an HSM, not *what the firmware supports*. For JCA software providers, capability is derivable from provider identity + version (a lookup table that itself needs sources). Expect `UNKNOWN` for HSM capability and say so.
- **JDK version is tier-relevant evidence.** VERIFIED (JDK 19 release notes, JDK-8267319): default key sizes rose — AES 128→256 if permitted by crypto policy, RSA/RSASSA-PSS/DH 2048→3072, EC 256→384. An unsized `KeyGenerator.getInstance("AES")` is therefore AES-128 (Grover tier) or AES-256 (not affected) depending on JDK line, and backports to earlier update lines are vendor/build-specific (VERIFY per build). Resolution requires the runtime JDK version from the image — a join with package/image evidence, scoped per T7. The harness pins one JDK build; "17/21" was ambiguous and is removed.

### 16.3 Freeze gate (must pass before PRV-001 is frozen)

1. SunJCE vs Bouncy Castle OAEP: same string, different MGF1; cross-decryption fails.
2. Unsized `KeyGenerator("AES")` / `KeyPairGenerator("RSA"|"EC")` on the pinned JDK build; record values in `experiments.md`. Optional contrast fixture on a JDK 17 build.
3. Node bundled OpenSSL ignores a system `openssl.cnf` that activates a provider under `openssl_conf` (default `nodejs_conf` behaviour).
