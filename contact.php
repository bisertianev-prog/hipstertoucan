<?php
/**
 * HipsterToucan — обработка на формата за контакт
 * МЯСТО: /home/hipstert/public_html/contact.php
 * Връща JSON: {"ok":true,"msg":"..."} или {"ok":false,"msg":"..."}
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');

/* ---------- помощни ---------- */

function respond(bool $ok, string $msg, int $code = 200): void {
    http_response_code($code);
    echo json_encode(['ok' => $ok, 'msg' => $msg], JSON_UNESCAPED_UNICODE);
    exit;
}

function client_ip(): string {
    // Зад Cloudflare реалният IP е в този хедър
    if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
        return $_SERVER['HTTP_CF_CONNECTING_IP'];
    }
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function mime_subject(string $s): string {
    return '=?UTF-8?B?' . base64_encode($s) . '?=';
}

/* ---------- конфигурация ---------- */

$configPath = dirname(__DIR__) . '/ht-config.php';
if (!is_file($configPath)) {
    error_log('contact.php: липсва ht-config.php');
    respond(false, 'Възникна техническа грешка. Моля, пишете директно на info@hipstertoucan.com', 500);
}
$cfg = require $configPath;

/* ---------- метод ---------- */

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    respond(false, 'Невалидна заявка.', 405);
}

/* ---------- honeypot ---------- */
// Полето "website" е скрито с CSS. Хората не го попълват, ботовете — да.
if (!empty($_POST['website'])) {
    // Отговаряме с успех, за да не се учи ботът
    respond(true, 'Благодарим! Съобщението е изпратено.');
}

/* ---------- rate limit ---------- */

$limit = (int)($cfg['rate_limit_per_hour'] ?? 0);
if ($limit > 0) {
    $tmpDir = $cfg['tmp_dir'] ?? sys_get_temp_dir();
    if (!is_dir($tmpDir)) { @mkdir($tmpDir, 0700, true); }
    $file = rtrim($tmpDir, '/') . '/ht_rl_' . md5(client_ip()) . '.json';

    $now  = time();
    $hits = [];
    if (is_file($file)) {
        $raw  = @file_get_contents($file);
        $hits = json_decode((string)$raw, true) ?: [];
    }
    // пазим само последния час
    $hits = array_values(array_filter($hits, fn($t) => ($now - (int)$t) < 3600));

    if (count($hits) >= $limit) {
        respond(false, 'Твърде много съобщения от този адрес. Опитайте отново след час.', 429);
    }
    $hits[] = $now;
    @file_put_contents($file, json_encode($hits), LOCK_EX);
}

/* ---------- Turnstile ---------- */

$secret = trim((string)($cfg['turnstile_secret'] ?? ''));
$token  = trim((string)($_POST['cf-turnstile-response'] ?? ''));

if ($secret === '' || $secret === 'ПОСТАВИ_ТУК_SECRET_KEY') {
    error_log('contact.php: Turnstile secret не е конфигуриран');
    respond(false, 'Възникна техническа грешка. Моля, пишете директно на info@hipstertoucan.com', 500);
}

if ($token === '') {
    respond(false, 'Моля, потвърдете проверката "Не съм робот".', 400);
}

$ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
curl_setopt_array($ch, [
    CURLOPT_POST           => true,
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_TIMEOUT        => 10,
    CURLOPT_POSTFIELDS     => http_build_query([
        'secret'   => $secret,
        'response' => $token,
        'remoteip' => client_ip(),
    ]),
]);
$verifyRaw = curl_exec($ch);
$curlErr   = curl_error($ch);
curl_close($ch);

if ($verifyRaw === false) {
    error_log('contact.php: Turnstile verify провален — ' . $curlErr);
    respond(false, 'Проверката за сигурност не успя. Моля, опитайте отново.', 502);
}

$verify = json_decode((string)$verifyRaw, true);
if (empty($verify['success'])) {
    respond(false, 'Проверката за сигурност не беше премината. Презаредете страницата и опитайте отново.', 400);
}

/* ---------- валидация на полетата ---------- */

$name    = trim((string)($_POST['name'] ?? ''));
$email   = trim((string)($_POST['email'] ?? ''));
$phone   = trim((string)($_POST['phone'] ?? ''));
$topic   = trim((string)($_POST['topic'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));

if ($name === '' || mb_strlen($name) > 100) {
    respond(false, 'Моля, въведете валидно име.', 400);
}
if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL) || mb_strlen($email) > 150) {
    respond(false, 'Моля, въведете валиден имейл адрес.', 400);
}
if ($message === '' || mb_strlen($message) < 5) {
    respond(false, 'Моля, напишете съобщение.', 400);
}
if (mb_strlen($message) > 5000) {
    respond(false, 'Съобщението е твърде дълго (максимум 5000 знака).', 400);
}
if ($phone !== '' && !preg_match('/^[0-9+()\s\-]{5,25}$/', $phone)) {
    respond(false, 'Моля, въведете валиден телефонен номер.', 400);
}

// защита срещу header injection
foreach ([$name, $email, $phone] as $v) {
    if (preg_match('/[\r\n]/', $v)) {
        respond(false, 'Невалидни данни.', 400);
    }
}

$topics = [
    'new-site' => 'Нов сайт',
    'update'   => 'Обновяване / оптимизация',
    'hosting'  => 'Хостинг и домейн',
    'other'    => 'Друго',
];
$topicLabel = $topics[$topic] ?? 'Не е посочена';

/* ---------- съставяне на писмото ---------- */

$body = "Ново запитване от hipstertoucan.com\n"
      . str_repeat('=', 40) . "\n\n"
      . "Име:       {$name}\n"
      . "Имейл:     {$email}\n"
      . "Телефон:   " . ($phone !== '' ? $phone : '—') . "\n"
      . "Тема:      {$topicLabel}\n\n"
      . "Съобщение:\n"
      . str_repeat('-', 40) . "\n"
      . $message . "\n"
      . str_repeat('-', 40) . "\n\n"
      . "IP:        " . client_ip() . "\n"
      . "Дата:      " . date('d.m.Y H:i:s') . "\n"
      . "Браузър:   " . substr((string)($_SERVER['HTTP_USER_AGENT'] ?? '—'), 0, 200) . "\n";

$fromEmail = $cfg['mail_from'];
$fromName  = $cfg['mail_from_name'] ?? 'HipsterToucan';

$headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'From: ' . mime_subject($fromName) . ' <' . $fromEmail . '>',
    'Reply-To: ' . mime_subject($name) . ' <' . $email . '>',
    'X-Mailer: HipsterToucan Contact Form',
];

$subject = mime_subject('Запитване от сайта: ' . $topicLabel . ' — ' . $name);

$sent = @mail(
    $cfg['mail_to'],
    $subject,
    $body,
    implode("\r\n", $headers),
    '-f' . $fromEmail
);

if (!$sent) {
    error_log('contact.php: mail() върна false');
    respond(false, 'Съобщението не можа да бъде изпратено. Моля, пишете директно на ' . $cfg['mail_to'], 500);
}

respond(true, 'Благодарим! Съобщението е изпратено — ще се свържем с Вас скоро.');
