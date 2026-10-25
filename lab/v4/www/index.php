<?php
// Benign landing page for the v4 lab.
header('Content-Type: text/html; charset=utf-8');
echo "<!doctype html><title>p2s lab</title><h1>php2shell v4 lab</h1>";
echo "<p>PHP " . htmlspecialchars(PHP_VERSION) . " / " . htmlspecialchars(PHP_SAPI) . "</p>";
echo "<p>worker " . getmypid() . "</p>";
