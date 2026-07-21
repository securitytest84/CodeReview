<?php
// Intentionally insecure demo code

$user = $_GET['user'] ?? '';
$command = "echo " . $user;
system($command);

$pdo = new PDO('mysql:host=localhost;dbname=demo', 'root', 'password');
$stmt = $pdo->query("SELECT * FROM users WHERE username = '$user'");
$rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
print_r($rows);
?>
