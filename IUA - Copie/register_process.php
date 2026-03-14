<?php
session_start();

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: register.html');
    exit;
}

$host = '127.0.0.1';
$dbname = 'havenmind';
$dbuser = 'root';
$dbpass = 'Annie05022jemael';

try {
    $pdo = new PDO(
        "mysql:host={$host};dbname={$dbname};charset=utf8mb4",
        $dbuser,
        $dbpass,
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (Throwable $e) {
    $_SESSION['register_errors'] = ['Connexion a la base de donnees impossible.'];
    header('Location: register.html');
    exit;
}

$firstname = trim($_POST['firstname'] ?? '');
$lastname = trim($_POST['lastname'] ?? '');
$email = trim($_POST['email'] ?? '');
$password = $_POST['password'] ?? '';
$confirmPassword = $_POST['confirm-password'] ?? '';
$termsAccepted = isset($_POST['terms']);

$errors = [];

if ($firstname === '') {
    $errors[] = 'Le prenom est obligatoire.';
}
if ($lastname === '') {
    $errors[] = 'Le nom est obligatoire.';
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    $errors[] = 'Adresse email invalide.';
}
if (strlen($password) < 8) {
    $errors[] = 'Le mot de passe doit contenir au moins 8 caracteres.';
}
if (!preg_match('/[A-Z]/', $password) || !preg_match('/[0-9]/', $password) || !preg_match('/[^A-Za-z0-9]/', $password)) {
    $errors[] = 'Le mot de passe doit contenir au moins 1 majuscule, 1 chiffre et 1 caractere special.';
}
if ($password !== $confirmPassword) {
    $errors[] = 'Les mots de passe ne correspondent pas.';
}
if (!$termsAccepted) {
    $errors[] = 'Vous devez accepter les conditions.';
}

if (!empty($errors)) {
    $_SESSION['register_errors'] = $errors;
    header('Location: register.html');
    exit;
}

$checkStmt = $pdo->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
$checkStmt->execute(['email' => $email]);

if ($checkStmt->fetch()) {
    $_SESSION['register_errors'] = ['Cet email est deja utilise.'];
    header('Location: register.html');
    exit;
}

$passwordHash = password_hash($password, PASSWORD_DEFAULT);

$insertStmt = $pdo->prepare(
    'INSERT INTO users (firstname, lastname, email, password_hash, created_at)
     VALUES (:firstname, :lastname, :email, :password_hash, NOW())'
);

$insertStmt->execute([
    'firstname' => $firstname,
    'lastname' => $lastname,
    'email' => $email,
    'password_hash' => $passwordHash,
]);

$_SESSION['register_success'] = 'Inscription terminee. Vous pouvez vous connecter.';
header('Location: login.html');
exit;
?>
