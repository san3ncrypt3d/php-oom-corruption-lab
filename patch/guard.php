<?php
// Stopgap guard for CVE-2026-109618 / -109619 when php.ini can't be edited.
// Deploy via auto_prepend_file (php.ini, .user.ini, or .htaccess php_value).
// Rejects the upload-progress injection field and forces cookie-only sessions.
// Not a fix -- the OOM core still needs the upstream patch / an upgrade.

(static function (): void {
    $field = ini_get('session.upload_progress.name') ?: 'PHP_SESSION_UPLOAD_PROGRESS';

    if (stripos($_SERVER['CONTENT_TYPE'] ?? '', 'multipart/form-data') !== false
        && array_key_exists($field, $_POST)) {
        http_response_code(400);
        header('Content-Type: text/plain');
        error_log(sprintf('[oom-guard] blocked %s from %s',
            $field, $_SERVER['REMOTE_ADDR'] ?? '?'));
        exit("Request rejected.\n");
    }

    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_strict_mode', '1');
    }
})();
