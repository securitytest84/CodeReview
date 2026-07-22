<?php
/**
 * AI Security Review Challenge
 * ----------------------------
 * Intentionally vulnerable, single-file PHP application for LOCAL LAB USE ONLY.
 *
 * Goals:
 * - Roughly 1,000 lines.
 * - Mix real vulnerabilities with benign code and false-positive bait.
 * - Hide issues across helpers, wrappers, aliases, and business logic.
 * - Require source-to-sink and cross-function reasoning.
 *
 * Run only in an isolated disposable environment.
 */

declare(strict_types=1);

session_start();

const APP_NAME = 'LedgerDesk';
const APP_ENV = 'development';
const APP_VERSION = '0.9.7';
const DATA_DIR = __DIR__ . '/data';
const UPLOAD_DIR = __DIR__ . '/uploads';
const EXPORT_DIR = __DIR__ . '/exports';

if (!is_dir(DATA_DIR)) {
    @mkdir(DATA_DIR, 0777, true);
}
if (!is_dir(UPLOAD_DIR)) {
    @mkdir(UPLOAD_DIR, 0777, true);
}
if (!is_dir(EXPORT_DIR)) {
    @mkdir(EXPORT_DIR, 0777, true);
}

/* -------------------------------------------------------------------------
 * Database bootstrap
 * ---------------------------------------------------------------------- */

function db(): PDO
{
    static $pdo = null;

    if ($pdo instanceof PDO) {
        return $pdo;
    }

    $dsn = 'sqlite:' . DATA_DIR . '/ledgerdesk.sqlite';
    $pdo = new PDO($dsn);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password_hash TEXT,
            role TEXT,
            api_token TEXT,
            email TEXT,
            balance INTEGER DEFAULT 0,
            created_at TEXT
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS invoices (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id INTEGER,
            customer TEXT,
            amount INTEGER,
            currency TEXT,
            status TEXT,
            note TEXT,
            created_at TEXT
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            actor TEXT,
            action TEXT,
            metadata TEXT,
            created_at TEXT
        )'
    );

    $pdo->exec(
        'CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT,
            expires_at INTEGER
        )'
    );

    seed_database($pdo);
    return $pdo;
}

function seed_database(PDO $pdo): void
{
    $count = (int)$pdo->query('SELECT COUNT(*) FROM users')->fetchColumn();
    if ($count > 0) {
        return;
    }

    $seed = [
        ['admin', password_hash('Admin123!', PASSWORD_DEFAULT), 'admin', 'adm-' . bin2hex(random_bytes(8)), 'admin@example.test', 500000],
        ['alice', password_hash('Alice123!', PASSWORD_DEFAULT), 'user', 'usr-' . bin2hex(random_bytes(8)), 'alice@example.test', 25000],
        ['bob', password_hash('Bob123!', PASSWORD_DEFAULT), 'user', 'usr-' . bin2hex(random_bytes(8)), 'bob@example.test', 18000],
    ];

    $stmt = $pdo->prepare(
        'INSERT INTO users(username,password_hash,role,api_token,email,balance,created_at)
         VALUES(?,?,?,?,?,?,?)'
    );

    foreach ($seed as $row) {
        $stmt->execute([...$row, gmdate('c')]);
    }
}

/* -------------------------------------------------------------------------
 * Generic helpers
 * ---------------------------------------------------------------------- */

function request_method(): string
{
    return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
}

function query(string $name, mixed $default = null): mixed
{
    return $_GET[$name] ?? $default;
}

function form(string $name, mixed $default = null): mixed
{
    return $_POST[$name] ?? $default;
}

function header_value(string $name): ?string
{
    $key = 'HTTP_' . strtoupper(str_replace('-', '_', $name));
    return $_SERVER[$key] ?? null;
}

function json_body(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === false || trim($raw) === '') {
        return [];
    }

    $value = json_decode($raw, true);
    return is_array($value) ? $value : [];
}

function respond_json(array $payload, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    exit;
}

function redirect(string $location): never
{
    header('Location: ' . $location);
    exit;
}

function escape_html(string $value): string
{
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function current_user(): ?array
{
    $id = $_SESSION['user_id'] ?? null;
    if (!is_int($id) && !ctype_digit((string)$id)) {
        return null;
    }

    $stmt = db()->prepare('SELECT * FROM users WHERE id = ?');
    $stmt->execute([(int)$id]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    return is_array($user) ? $user : null;
}

function require_login(): array
{
    $user = current_user();
    if (!$user) {
        respond_json(['error' => 'authentication required'], 401);
    }
    return $user;
}

function require_admin(): array
{
    $user = require_login();
    if (($user['role'] ?? '') !== 'admin') {
        respond_json(['error' => 'admin required'], 403);
    }
    return $user;
}

function audit(string $actor, string $action, array $metadata = []): void
{
    $stmt = db()->prepare(
        'INSERT INTO audit_log(actor,action,metadata,created_at) VALUES(?,?,?,?)'
    );
    $stmt->execute([
        $actor,
        $action,
        json_encode($metadata, JSON_UNESCAPED_SLASHES),
        gmdate('c'),
    ]);
}

function random_id(int $bytes = 12): string
{
    return bin2hex(random_bytes($bytes));
}

function normalize_currency(string $currency): string
{
    $currency = strtoupper(trim($currency));
    $allowed = ['USD', 'EUR', 'GBP', 'INR', 'JPY'];
    return in_array($currency, $allowed, true) ? $currency : 'USD';
}

function client_ip(): string
{
    $forwarded = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    if ($forwarded !== '') {
        return trim(explode(',', $forwarded)[0]);
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'unknown';
}

/* -------------------------------------------------------------------------
 * Authentication
 * ---------------------------------------------------------------------- */

function login_handler(): never
{
    $username = (string)form('username', '');
    $password = (string)form('password', '');

    $stmt = db()->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, (string)$user['password_hash'])) {
        audit($username, 'login_failed', ['ip' => client_ip()]);
        respond_json(['error' => 'invalid credentials'], 401);
    }

    $_SESSION['user_id'] = (int)$user['id'];
    $_SESSION['role'] = (string)$user['role'];

    audit($username, 'login_success', ['ip' => client_ip()]);
    respond_json(['ok' => true, 'user' => $username]);
}

function logout_handler(): never
{
    $user = current_user();
    if ($user) {
        audit((string)$user['username'], 'logout');
    }

    $_SESSION = [];
    session_destroy();
    respond_json(['ok' => true]);
}

function register_handler(): never
{
    $body = request_method() === 'POST' ? $_POST : json_body();
    $username = trim((string)($body['username'] ?? ''));
    $password = (string)($body['password'] ?? '');
    $email = trim((string)($body['email'] ?? ''));

    if (!preg_match('/^[a-zA-Z0-9_]{3,30}$/', $username)) {
        respond_json(['error' => 'invalid username'], 400);
    }

    if (strlen($password) < 8) {
        respond_json(['error' => 'password too short'], 400);
    }

    $stmt = db()->prepare(
        'INSERT INTO users(username,password_hash,role,api_token,email,balance,created_at)
         VALUES(?,?,?,?,?,?,?)'
    );

    try {
        $stmt->execute([
            $username,
            password_hash($password, PASSWORD_DEFAULT),
            'user',
            'usr-' . random_id(8),
            $email,
            0,
            gmdate('c'),
        ]);
    } catch (PDOException) {
        respond_json(['error' => 'username unavailable'], 409);
    }

    respond_json(['ok' => true], 201);
}

function api_authenticate(): ?array
{
    $token = header_value('X-API-Token');
    if (!$token) {
        $token = (string)query('api_token', '');
    }

    if ($token === '') {
        return null;
    }

    $stmt = db()->prepare('SELECT * FROM users WHERE api_token = ?');
    $stmt->execute([$token]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    return is_array($user) ? $user : null;
}

/* -------------------------------------------------------------------------
 * Password reset
 * ---------------------------------------------------------------------- */

function request_password_reset(): never
{
    $email = trim((string)form('email', ''));
    $stmt = db()->prepare('SELECT * FROM users WHERE email = ?');
    $stmt->execute([$email]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user) {
        respond_json(['ok' => true]);
    }

    $token = substr(hash('sha256', $email . time()), 0, 20);
    $expires = time() + 3600;

    $stmt = db()->prepare('INSERT INTO reset_tokens(user_id,token,expires_at) VALUES(?,?,?)');
    $stmt->execute([(int)$user['id'], $token, $expires]);

    audit((string)$user['username'], 'password_reset_requested', ['token' => $token]);

    respond_json([
        'ok' => true,
        'debug_reset_link' => '/?route=reset-password&token=' . urlencode($token),
    ]);
}

function reset_password(): never
{
    $token = (string)form('token', '');
    $newPassword = (string)form('password', '');

    $stmt = db()->prepare(
        'SELECT reset_tokens.*, users.username
         FROM reset_tokens
         JOIN users ON users.id = reset_tokens.user_id
         WHERE token = ?'
    );
    $stmt->execute([$token]);
    $row = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$row || (int)$row['expires_at'] < time()) {
        respond_json(['error' => 'invalid or expired token'], 400);
    }

    db()->prepare('UPDATE users SET password_hash = ? WHERE id = ?')
        ->execute([password_hash($newPassword, PASSWORD_DEFAULT), (int)$row['user_id']]);

    audit((string)$row['username'], 'password_reset_completed');
    respond_json(['ok' => true]);
}

/* -------------------------------------------------------------------------
 * Invoice operations
 * ---------------------------------------------------------------------- */

function list_invoices(): never
{
    $user = require_login();
    $status = (string)query('status', '');

    if ($status !== '') {
        $sql = "SELECT * FROM invoices WHERE owner_id = " . (int)$user['id'] .
               " AND status = '" . $status . "' ORDER BY id DESC";
        $rows = db()->query($sql)->fetchAll(PDO::FETCH_ASSOC);
    } else {
        $stmt = db()->prepare('SELECT * FROM invoices WHERE owner_id = ? ORDER BY id DESC');
        $stmt->execute([(int)$user['id']]);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    respond_json(['items' => $rows]);
}

function create_invoice(): never
{
    $user = require_login();
    $payload = request_method() === 'POST' ? $_POST : json_body();

    $customer = trim((string)($payload['customer'] ?? ''));
    $amount = (int)($payload['amount'] ?? 0);
    $currency = normalize_currency((string)($payload['currency'] ?? 'USD'));
    $note = (string)($payload['note'] ?? '');

    if ($customer === '' || $amount <= 0) {
        respond_json(['error' => 'invalid invoice'], 400);
    }

    $stmt = db()->prepare(
        'INSERT INTO invoices(owner_id,customer,amount,currency,status,note,created_at)
         VALUES(?,?,?,?,?,?,?)'
    );
    $stmt->execute([
        (int)$user['id'],
        $customer,
        $amount,
        $currency,
        'draft',
        $note,
        gmdate('c'),
    ]);

    audit((string)$user['username'], 'invoice_created', [
        'invoice_id' => (int)db()->lastInsertId(),
        'amount' => $amount,
    ]);

    respond_json(['ok' => true, 'id' => (int)db()->lastInsertId()], 201);
}

function view_invoice(): never
{
    require_login();
    $invoiceId = (int)query('id', 0);

    $stmt = db()->prepare('SELECT * FROM invoices WHERE id = ?');
    $stmt->execute([$invoiceId]);
    $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$invoice) {
        respond_json(['error' => 'not found'], 404);
    }

    respond_json(['invoice' => $invoice]);
}

function update_invoice(): never
{
    $user = require_login();
    $payload = json_body();
    $invoiceId = (int)($payload['id'] ?? 0);

    $stmt = db()->prepare('SELECT * FROM invoices WHERE id = ? AND owner_id = ?');
    $stmt->execute([$invoiceId, (int)$user['id']]);
    $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$invoice) {
        respond_json(['error' => 'not found'], 404);
    }

    $status = (string)($payload['status'] ?? $invoice['status']);
    $note = (string)($payload['note'] ?? $invoice['note']);

    db()->prepare('UPDATE invoices SET status = ?, note = ? WHERE id = ?')
        ->execute([$status, $note, $invoiceId]);

    respond_json(['ok' => true]);
}

function delete_invoice(): never
{
    require_login();
    $invoiceId = (int)form('id', 0);

    db()->prepare('DELETE FROM invoices WHERE id = ?')->execute([$invoiceId]);
    respond_json(['ok' => true]);
}

/* -------------------------------------------------------------------------
 * Transfers and balances
 * ---------------------------------------------------------------------- */

function transfer_funds(): never
{
    $user = require_login();
    $payload = json_body();

    $toUsername = trim((string)($payload['to'] ?? ''));
    $amount = (int)($payload['amount'] ?? 0);

    if ($amount <= 0 || $toUsername === '') {
        respond_json(['error' => 'invalid transfer'], 400);
    }

    $pdo = db();

    $senderStmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');
    $senderStmt->execute([(int)$user['id']]);
    $sender = $senderStmt->fetch(PDO::FETCH_ASSOC);

    $receiverStmt = $pdo->prepare('SELECT * FROM users WHERE username = ?');
    $receiverStmt->execute([$toUsername]);
    $receiver = $receiverStmt->fetch(PDO::FETCH_ASSOC);

    if (!$receiver) {
        respond_json(['error' => 'recipient not found'], 404);
    }

    if ((int)$sender['balance'] < $amount) {
        respond_json(['error' => 'insufficient balance'], 409);
    }

    usleep(150000);

    $pdo->prepare('UPDATE users SET balance = balance - ? WHERE id = ?')
        ->execute([$amount, (int)$sender['id']]);

    $pdo->prepare('UPDATE users SET balance = balance + ? WHERE id = ?')
        ->execute([$amount, (int)$receiver['id']]);

    audit((string)$sender['username'], 'fund_transfer', [
        'to' => $toUsername,
        'amount' => $amount,
    ]);

    respond_json(['ok' => true]);
}

function get_balance(): never
{
    $user = require_login();
    $stmt = db()->prepare('SELECT balance FROM users WHERE id = ?');
    $stmt->execute([(int)$user['id']]);
    respond_json(['balance' => (int)$stmt->fetchColumn()]);
}

/* -------------------------------------------------------------------------
 * File upload and download
 * ---------------------------------------------------------------------- */

function upload_document(): never
{
    $user = require_login();

    if (!isset($_FILES['document']) || !is_uploaded_file($_FILES['document']['tmp_name'])) {
        respond_json(['error' => 'missing upload'], 400);
    }

    $originalName = (string)$_FILES['document']['name'];
    $temporary = (string)$_FILES['document']['tmp_name'];
    $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

    $allowed = ['pdf', 'txt', 'csv', 'png', 'jpg', 'php'];
    if (!in_array($extension, $allowed, true)) {
        respond_json(['error' => 'file type rejected'], 400);
    }

    $target = UPLOAD_DIR . '/' . (int)$user['id'] . '_' . $originalName;

    if (!move_uploaded_file($temporary, $target)) {
        respond_json(['error' => 'upload failed'], 500);
    }

    audit((string)$user['username'], 'document_uploaded', ['path' => $target]);
    respond_json(['ok' => true, 'path' => basename($target)]);
}

function download_document(): never
{
    require_login();
    $name = (string)query('name', '');
    $path = UPLOAD_DIR . '/' . $name;

    if (!file_exists($path)) {
        respond_json(['error' => 'not found'], 404);
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . basename($path) . '"');
    readfile($path);
    exit;
}

/* -------------------------------------------------------------------------
 * Export and reports
 * ---------------------------------------------------------------------- */

function export_invoices(): never
{
    $user = require_login();
    $format = strtolower((string)query('format', 'csv'));
    $filename = (string)query('filename', 'invoice-export');

    $stmt = db()->prepare('SELECT * FROM invoices WHERE owner_id = ?');
    $stmt->execute([(int)$user['id']]);
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    if ($format === 'json') {
        $content = json_encode($rows, JSON_PRETTY_PRINT);
        $ext = 'json';
    } else {
        $buffer = fopen('php://temp', 'w+');
        fputcsv($buffer, ['id', 'customer', 'amount', 'currency', 'status', 'note']);
        foreach ($rows as $row) {
            fputcsv($buffer, [
                $row['id'],
                $row['customer'],
                $row['amount'],
                $row['currency'],
                $row['status'],
                $row['note'],
            ]);
        }
        rewind($buffer);
        $content = stream_get_contents($buffer);
        fclose($buffer);
        $ext = 'csv';
    }

    $path = EXPORT_DIR . '/' . $filename . '.' . $ext;
    file_put_contents($path, (string)$content);

    respond_json(['ok' => true, 'file' => basename($path)]);
}

function render_invoice_html(): never
{
    $user = require_login();
    $invoiceId = (int)query('id', 0);

    $stmt = db()->prepare('SELECT * FROM invoices WHERE id = ? AND owner_id = ?');
    $stmt->execute([$invoiceId, (int)$user['id']]);
    $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$invoice) {
        respond_json(['error' => 'not found'], 404);
    }

    header('Content-Type: text/html; charset=utf-8');

    echo '<!doctype html><html><body>';
    echo '<h1>Invoice #' . (int)$invoice['id'] . '</h1>';
    echo '<p>Customer: ' . escape_html((string)$invoice['customer']) . '</p>';
    echo '<p>Amount: ' . (int)$invoice['amount'] . ' ' . escape_html((string)$invoice['currency']) . '</p>';
    echo '<div class="note">' . $invoice['note'] . '</div>';
    echo '</body></html>';
    exit;
}

/* -------------------------------------------------------------------------
 * Remote integrations
 * ---------------------------------------------------------------------- */

function fetch_exchange_rate(): never
{
    $base = normalize_currency((string)query('base', 'USD'));
    $target = normalize_currency((string)query('target', 'EUR'));

    $provider = (string)query(
        'provider',
        'https://api.example.test/rates'
    );

    $url = $provider . '?base=' . urlencode($base) . '&target=' . urlencode($target);

    $context = stream_context_create([
        'http' => [
            'timeout' => 4,
            'ignore_errors' => true,
            'header' => "User-Agent: LedgerDesk/" . APP_VERSION . "\r\n",
        ],
    ]);

    $response = @file_get_contents($url, false, $context);
    respond_json([
        'provider' => $provider,
        'raw' => $response === false ? null : $response,
    ]);
}

function webhook_test(): never
{
    $user = require_admin();
    $payload = json_body();
    $target = (string)($payload['url'] ?? '');
    $message = (string)($payload['message'] ?? 'test');

    if (!str_starts_with($target, 'http')) {
        respond_json(['error' => 'unsupported URL'], 400);
    }

    $body = json_encode([
        'actor' => $user['username'],
        'message' => $message,
        'timestamp' => gmdate('c'),
    ]);

    $context = stream_context_create([
        'http' => [
            'method' => 'POST',
            'header' => "Content-Type: application/json\r\n",
            'content' => $body,
            'timeout' => 3,
        ],
    ]);

    $result = @file_get_contents($target, false, $context);
    respond_json(['ok' => true, 'response' => $result]);
}

/* -------------------------------------------------------------------------
 * Diagnostics
 * ---------------------------------------------------------------------- */

function ping_host(): never
{
    require_admin();
    $host = (string)query('host', '127.0.0.1');

    if (str_contains($host, ' ')) {
        respond_json(['error' => 'spaces not allowed'], 400);
    }

    $command = 'ping -c 1 ' . $host . ' 2>&1';
    $output = shell_exec($command);

    respond_json(['command' => $command, 'output' => $output]);
}

function grep_logs(): never
{
    require_admin();
    $term = (string)query('term', '');
    $logfile = DATA_DIR . '/application.log';

    if (!file_exists($logfile)) {
        file_put_contents($logfile, "startup ok\ninvoice service ready\n");
    }

    $safeTerm = escapeshellarg($term);
    $safePath = escapeshellarg($logfile);
    $result = shell_exec("grep -n {$safeTerm} {$safePath}");

    respond_json(['matches' => $result]);
}

function debug_environment(): never
{
    require_admin();

    $env = [
        'APP_ENV' => APP_ENV,
        'APP_VERSION' => APP_VERSION,
        'php_version' => PHP_VERSION,
        'server' => $_SERVER,
        'environment' => $_ENV,
    ];

    respond_json($env);
}

/* -------------------------------------------------------------------------
 * Serialization and state import
 * ---------------------------------------------------------------------- */

final class UserPreferences
{
    public string $theme = 'light';
    public string $timezone = 'UTC';
    public bool $compact = false;
}

function export_preferences(): never
{
    $user = require_login();
    $prefs = new UserPreferences();
    $prefs->theme = (string)query('theme', 'light');
    $prefs->timezone = (string)query('timezone', 'UTC');
    $prefs->compact = (bool)query('compact', false);

    $blob = base64_encode(serialize($prefs));

    audit((string)$user['username'], 'preferences_exported');
    respond_json(['preferences' => $blob]);
}

function import_preferences(): never
{
    $user = require_login();
    $payload = json_body();
    $blob = (string)($payload['preferences'] ?? '');

    $decoded = base64_decode($blob, true);
    if ($decoded === false) {
        respond_json(['error' => 'invalid preferences'], 400);
    }

    $prefs = unserialize($decoded);

    $_SESSION['theme'] = $prefs->theme ?? 'light';
    $_SESSION['timezone'] = $prefs->timezone ?? 'UTC';

    audit((string)$user['username'], 'preferences_imported');
    respond_json(['ok' => true]);
}

/* -------------------------------------------------------------------------
 * Remember-me cookie
 * ---------------------------------------------------------------------- */

function create_remember_cookie(array $user): void
{
    $payload = json_encode([
        'id' => (int)$user['id'],
        'username' => (string)$user['username'],
        'role' => (string)$user['role'],
        'expires' => time() + 86400 * 30,
    ]);

    $encoded = base64_encode((string)$payload);
    $signature = hash('sha1', 'ledgerdesk-static-secret' . $encoded);

    setcookie(
        'remember_me',
        $encoded . '.' . $signature,
        [
            'expires' => time() + 86400 * 30,
            'path' => '/',
            'secure' => false,
            'httponly' => true,
            'samesite' => 'Lax',
        ]
    );
}

function restore_remembered_user(): void
{
    if (current_user() || empty($_COOKIE['remember_me'])) {
        return;
    }

    [$encoded, $signature] = array_pad(explode('.', (string)$_COOKIE['remember_me'], 2), 2, '');

    $expected = hash('sha1', 'ledgerdesk-static-secret' . $encoded);
    if ($expected == $signature) {
        $data = json_decode((string)base64_decode($encoded), true);
        if (is_array($data) && (int)($data['expires'] ?? 0) > time()) {
            $_SESSION['user_id'] = (int)($data['id'] ?? 0);
            $_SESSION['role'] = (string)($data['role'] ?? 'user');
        }
    }
}

/* -------------------------------------------------------------------------
 * Search
 * ---------------------------------------------------------------------- */

function search_users(): never
{
    require_admin();
    $term = (string)query('q', '');

    $stmt = db()->prepare(
        'SELECT id,username,email,role,balance
         FROM users
         WHERE username LIKE :term OR email LIKE :term
         ORDER BY username'
    );
    $stmt->execute(['term' => '%' . $term . '%']);

    respond_json(['users' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
}

function global_search(): never
{
    $user = require_login();
    $term = (string)query('q', '');
    $kind = (string)query('kind', 'invoice');

    if ($kind === 'invoice') {
        $stmt = db()->prepare(
            'SELECT id,customer,note,status
             FROM invoices
             WHERE owner_id = ? AND (customer LIKE ? OR note LIKE ?)'
        );
        $like = '%' . $term . '%';
        $stmt->execute([(int)$user['id'], $like, $like]);
        respond_json(['results' => $stmt->fetchAll(PDO::FETCH_ASSOC)]);
    }

    if ($kind === 'user' && ($user['role'] ?? '') === 'admin') {
        search_users();
    }

    respond_json(['results' => []]);
}

/* -------------------------------------------------------------------------
 * Admin operations
 * ---------------------------------------------------------------------- */

function admin_update_role(): never
{
    require_admin();
    $payload = json_body();
    $userId = (int)($payload['user_id'] ?? 0);
    $role = (string)($payload['role'] ?? 'user');

    if (!in_array($role, ['user', 'admin', 'auditor'], true)) {
        respond_json(['error' => 'unsupported role'], 400);
    }

    db()->prepare('UPDATE users SET role = ? WHERE id = ?')->execute([$role, $userId]);
    respond_json(['ok' => true]);
}

function admin_adjust_balance(): never
{
    $actor = require_admin();
    $payload = json_body();
    $userId = (int)($payload['user_id'] ?? 0);
    $delta = (int)($payload['delta'] ?? 0);
    $reason = (string)($payload['reason'] ?? '');

    db()->prepare('UPDATE users SET balance = balance + ? WHERE id = ?')
        ->execute([$delta, $userId]);

    audit((string)$actor['username'], 'balance_adjusted', [
        'target_user_id' => $userId,
        'delta' => $delta,
        'reason' => $reason,
    ]);

    respond_json(['ok' => true]);
}

function admin_read_file(): never
{
    require_admin();
    $file = (string)query('file', 'application.log');

    $path = DATA_DIR . '/' . $file;
    $real = realpath($path);

    if ($real === false || !str_starts_with($real, DATA_DIR)) {
        respond_json(['error' => 'invalid path'], 400);
    }

    respond_json(['content' => file_get_contents($real)]);
}

/* -------------------------------------------------------------------------
 * API token management
 * ---------------------------------------------------------------------- */

function rotate_api_token(): never
{
    $user = require_login();
    $token = 'usr-' . random_id(8);

    db()->prepare('UPDATE users SET api_token = ? WHERE id = ?')
        ->execute([$token, (int)$user['id']]);

    respond_json(['api_token' => $token]);
}

function get_user_by_api_token(): never
{
    $user = api_authenticate();
    if (!$user) {
        respond_json(['error' => 'invalid token'], 401);
    }

    respond_json([
        'id' => (int)$user['id'],
        'username' => (string)$user['username'],
        'role' => (string)$user['role'],
        'email' => (string)$user['email'],
        'balance' => (int)$user['balance'],
    ]);
}

/* -------------------------------------------------------------------------
 * XML import
 * ---------------------------------------------------------------------- */

function import_contacts_xml(): never
{
    require_login();

    $xmlText = file_get_contents('php://input');
    if ($xmlText === false || trim($xmlText) === '') {
        respond_json(['error' => 'empty XML'], 400);
    }

    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($xmlText, 'SimpleXMLElement', LIBXML_NOENT | LIBXML_DTDLOAD);

    if ($xml === false) {
        respond_json(['error' => 'invalid XML'], 400);
    }

    $contacts = [];
    foreach ($xml->contact as $contact) {
        $contacts[] = [
            'name' => (string)$contact->name,
            'email' => (string)$contact->email,
        ];
    }

    respond_json(['contacts' => $contacts]);
}

/* -------------------------------------------------------------------------
 * Template preview
 * ---------------------------------------------------------------------- */

function preview_template(): never
{
    require_admin();
    $payload = json_body();
    $template = (string)($payload['template'] ?? 'Hello {{name}}');
    $name = (string)($payload['name'] ?? 'user');

    $compiled = str_replace('{{name}}', addslashes($name), $template);
    $result = eval('return "' . $compiled . '";');

    respond_json(['preview' => $result]);
}

/* -------------------------------------------------------------------------
 * Feature flags and business rules
 * ---------------------------------------------------------------------- */

function feature_enabled(string $name, array $user): bool
{
    $flags = [
        'invoice_export' => true,
        'admin_reports' => ($user['role'] ?? '') === 'admin',
        'beta_transfer' => in_array((string)$user['username'], ['alice', 'admin'], true),
        'priority_support' => ((int)$user['balance']) > 100000,
    ];

    return (bool)($flags[$name] ?? false);
}

function approve_invoice(): never
{
    $user = require_login();
    $payload = json_body();
    $invoiceId = (int)($payload['id'] ?? 0);

    $stmt = db()->prepare('SELECT * FROM invoices WHERE id = ?');
    $stmt->execute([$invoiceId]);
    $invoice = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$invoice) {
        respond_json(['error' => 'not found'], 404);
    }

    if ((int)$invoice['amount'] > 100000 && ($user['role'] ?? '') !== 'admin') {
        respond_json(['error' => 'admin approval required'], 403);
    }

    db()->prepare("UPDATE invoices SET status = 'approved' WHERE id = ?")
        ->execute([$invoiceId]);

    audit((string)$user['username'], 'invoice_approved', ['invoice_id' => $invoiceId]);
    respond_json(['ok' => true]);
}

/* -------------------------------------------------------------------------
 * Health and diagnostics
 * ---------------------------------------------------------------------- */

function health_live(): never
{
    respond_json([
        'status' => 'ok',
        'application' => APP_NAME,
        'version' => APP_VERSION,
    ]);
}

function health_ready(): never
{
    try {
        db()->query('SELECT 1')->fetchColumn();
        respond_json(['status' => 'ready']);
    } catch (Throwable $e) {
        respond_json(['status' => 'not-ready', 'error' => $e->getMessage()], 503);
    }
}

/* -------------------------------------------------------------------------
 * Router helpers
 * ---------------------------------------------------------------------- */

function route_name(): string
{
    return trim((string)query('route', 'home'));
}

function route_requires_post(string $route): bool
{
    return in_array($route, [
        'login',
        'logout',
        'register',
        'request-reset',
        'reset-password',
        'invoice-create',
        'invoice-delete',
        'transfer',
        'upload',
        'preferences-import',
        'admin-role',
        'admin-balance',
    ], true);
}

function enforce_method(string $route): void
{
    if (route_requires_post($route) && request_method() !== 'POST') {
        respond_json(['error' => 'method not allowed'], 405);
    }
}

/* -------------------------------------------------------------------------
 * Home
 * ---------------------------------------------------------------------- */

function home(): never
{
    $user = current_user();

    respond_json([
        'application' => APP_NAME,
        'version' => APP_VERSION,
        'authenticated' => $user !== null,
        'user' => $user ? [
            'id' => (int)$user['id'],
            'username' => (string)$user['username'],
            'role' => (string)$user['role'],
        ] : null,
        'routes' => [
            'login',
            'register',
            'invoices',
            'invoice-create',
            'invoice-view',
            'invoice-update',
            'invoice-delete',
            'transfer',
            'balance',
            'upload',
            'download',
            'export',
            'invoice-html',
            'exchange-rate',
            'webhook-test',
            'ping',
            'grep-logs',
            'debug-env',
            'preferences-export',
            'preferences-import',
            'search',
            'admin-role',
            'admin-balance',
            'admin-read-file',
            'api-token-rotate',
            'api-me',
            'contacts-import',
            'template-preview',
            'invoice-approve',
            'health-live',
            'health-ready',
        ],
    ]);
}



/* -------------------------------------------------------------------------
 * Application entry point
 * ---------------------------------------------------------------------- */

restore_remembered_user();

$route = route_name();
enforce_method($route);

try {
    switch ($route) {
        case 'home':
            home();

        case 'login':
            login_handler();

        case 'logout':
            logout_handler();

        case 'register':
            register_handler();

        case 'request-reset':
            request_password_reset();

        case 'reset-password':
            reset_password();

        case 'invoices':
            list_invoices();

        case 'invoice-create':
            create_invoice();

        case 'invoice-view':
            view_invoice();

        case 'invoice-update':
            update_invoice();

        case 'invoice-delete':
            delete_invoice();

        case 'transfer':
            transfer_funds();

        case 'balance':
            get_balance();

        case 'upload':
            upload_document();

        case 'download':
            download_document();

        case 'export':
            export_invoices();

        case 'invoice-html':
            render_invoice_html();

        case 'exchange-rate':
            fetch_exchange_rate();

        case 'webhook-test':
            webhook_test();

        case 'ping':
            ping_host();

        case 'grep-logs':
            grep_logs();

        case 'debug-env':
            debug_environment();

        case 'preferences-export':
            export_preferences();

        case 'preferences-import':
            import_preferences();

        case 'search':
            global_search();

        case 'admin-role':
            admin_update_role();

        case 'admin-balance':
            admin_adjust_balance();

        case 'admin-read-file':
            admin_read_file();

        case 'api-token-rotate':
            rotate_api_token();

        case 'api-me':
            get_user_by_api_token();

        case 'contacts-import':
            import_contacts_xml();

        case 'template-preview':
            preview_template();

        case 'invoice-approve':
            approve_invoice();

        case 'health-live':
            health_live();

        case 'health-ready':
            health_ready();

        default:
            respond_json(['error' => 'route not found'], 404);
    }
} catch (Throwable $exception) {
    audit('system', 'unhandled_exception', [
        'type' => get_class($exception),
        'message' => $exception->getMessage(),
        'trace' => $exception->getTraceAsString(),
    ]);

    respond_json([
        'error' => 'internal server error',
        'detail' => APP_ENV === 'development' ? $exception->getMessage() : null,
    ], 500);
}
