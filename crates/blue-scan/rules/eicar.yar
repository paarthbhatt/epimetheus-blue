/*
 * EICAR — the industry-standard antivirus test string.
 *
 * The payload is harmless by construction; scanners agree to flag it without
 * shipping real malware. This rule exists so the scan path can be exercised
 * end to end in tests and in a live drill.
 */
rule eicar_test_string
{
    meta:
        description = "EICAR antivirus test file"
        confidence = "high"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
