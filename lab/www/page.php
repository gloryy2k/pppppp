<?php
session_start();

$pages = ['about', 'contact', 'help'];
$p = $_GET['p'] ?? 'about';

if (in_array($p, $pages) && file_exists(__DIR__ . "/pages/$p.php")) {
    include __DIR__ . "/pages/$p.php";
} else {
    echo "<h1>404</h1><p>Page not found.</p>";
}
