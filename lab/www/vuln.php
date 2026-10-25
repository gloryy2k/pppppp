<?php
/**
 * Deliberately vulnerable page for lab testing ONLY.
 * Contains a local file inclusion (LFI) vulnerability.
 * DO NOT deploy to production.
 */
session_start();

$file = $_GET['file'] ?? '';
if ($file) {
    // Vulnerable: no sanitisation, allows path traversal
    @include($file);
} else {
    echo "<h1>Lab LFI Test</h1>";
    echo "<p>Usage: ?file=/path/to/file</p>";
}
