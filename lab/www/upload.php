<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])) {
    $uploadDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }
    $name = basename($_FILES['file']['name']);
    $dest = $uploadDir . $name;
    if (move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        $msg = "File uploaded: " . htmlspecialchars($name);
    } else {
        $msg = "Upload failed.";
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Upload</title></head>
<body>
<h1>File Upload</h1>
<?php if (isset($msg)) echo "<p>$msg</p>"; ?>
<form method="POST" enctype="multipart/form-data">
    <input type="file" name="file">
    <button type="submit">Upload</button>
</form>
<p><a href="/">Back</a></p>
</body>
</html>
