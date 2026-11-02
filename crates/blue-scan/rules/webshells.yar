/*
 * Generic PHP webshell indicators.
 *
 * These are deliberately broad and deliberately low confidence: a single hit
 * is a T1 candidate, never an infection. Corroboration (a second detector, or
 * a human looking at the file) is what promotes it. None of these strings is
 * malicious on its own, and they are authored here rather than copied from a
 * signature feed.
 */
rule webshell_eval_post
{
    meta:
        description = "PHP eval over POST input"
        confidence = "low"
        severity = "suspicious"
    strings:
        $a = "eval($_POST"
        $b = "eval ($_POST"
    condition:
        any of them
}

rule webshell_eval_request
{
    meta:
        description = "PHP eval over REQUEST input"
        confidence = "low"
        severity = "suspicious"
    strings:
        $a = "eval($_REQUEST"
        $b = "eval ($_REQUEST"
    condition:
        any of them
}

rule webshell_base64_system
{
    meta:
        description = "base64 decoding feeding a command executor"
        confidence = "low"
        severity = "suspicious"
    strings:
        $decode = "base64_decode("
        $exec = "system("
    condition:
        all of them
}

rule webshell_passthru_or_shell_exec
{
    meta:
        description = "PHP passthru/shell_exec reading from a GET parameter"
        confidence = "low"
        severity = "suspicious"
    strings:
        $passthru = "passthru($_GET"
        $shell_exec = "shell_exec($_GET"
    condition:
        any of them
}
