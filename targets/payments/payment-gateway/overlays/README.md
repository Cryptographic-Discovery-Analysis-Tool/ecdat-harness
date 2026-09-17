# PAY-001 state matrix overlays (harness §14.3)

States B, C, D, E, F, G, H are all reachable from the base fixture (as
committed: `src/main/resources/application.yml` = state B's OAEP value,
`application-prod.yml` = state D's PKCS1 value) by varying how the JVM is
launched -- no source changes needed, because Spring Boot reads env vars,
`-D` system properties, CLI args and profiles identically regardless of
whether a human or a Kubernetes Deployment set them. Only **state A** needs
an actual file overlay (`state-A/application.yml`, which drops the
`pay.keywrap` key entirely).

Real launch commands used for `harness/eval/validate_cfg_r1.py` (Lock §6
CFG-R1), against the packaged jar unless noted:

| State | Command (on top of `java -jar payment-gateway.jar`) |
|---|---|
| A | overlay `state-A/application.yml` over the packaged resource, rebuild, run with no other args |
| B | no overlay, no args (base fixture as committed) |
| C | env `PAY_KEYWRAP_TRANSFORMATION=RSA/ECB/PKCS1Padding` |
| D | env `SPRING_PROFILES_ACTIVE=prod` (uses the committed `application-prod.yml`) |
| E | env `SPRING_PROFILES_ACTIVE=prod PAY_KEYWRAP_TRANSFORMATION=RSA/ECB/PKCS1Padding` |
| F | CLI arg `--pay.keywrap.transformation=RSA/ECB/PKCS1Padding` |
| G | no run -- Helm `values.yaml` with an unreferenced key has zero effect on the running app; runtime is identical to B by construction, not by test |
| H | run from a working directory containing `./config/application.yml` = PKCS1 (Spring Boot's external `config/` directory search path beats the packaged classpath resource) |
