<?php
session_start();
?>
<!DOCTYPE html>
<html>
<head><title>Simple Blog</title></head>
<body>
<h1>My Blog</h1>
<p>PHP <?= phpversion() ?> | SAPI: <?= php_sapi_name() ?></p>
<nav>
    <a href="/">Home</a> |
    <a href="/upload.php">Upload</a> |
    <a href="/page.php?p=about">About</a> |
    <a href="/status.php">Status</a>
</nav>
<hr>
<p>Welcome to the blog. This is a simple PHP application.</p>
<?php if (isset($_SESSION['user'])): ?>
    <p>Logged in as: <?= htmlspecialchars($_SESSION['user']) ?></p>
<?php endif; ?>
</body>
</html>
