<?php
// Exposure report. Detection only.
header('Content-Type: application/json');

function ini_on($k) { return filter_var(ini_get($k), FILTER_VALIDATE_BOOL); }

$fixed = ['8.2' => '8.2.35', '8.3' => '8.3.36', '8.4' => '8.4.27', '8.5' => '8.5.12'];
$branch = PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION;
$version_vulnerable = null;
if (isset($fixed[$branch])) {
    $version_vulnerable = version_compare(PHP_VERSION, $fixed[$branch], '<');
} elseif (version_compare($branch, '8.2', '<')) {
    $version_vulnerable = true; // EOL, never patched
}

echo json_encode([
    'php_version'            => PHP_VERSION,
    'sapi'                   => PHP_SAPI,
    'branch'                 => $branch,
    'fixed_version_for_branch' => $fixed[$branch] ?? 'EOL / no fix',
    'version_vulnerable'     => $version_vulnerable,
    'conditions' => [
        'upload_progress_enabled' => ini_on('session.upload_progress.enabled'),
        'use_only_cookies'        => ini_on('session.use_only_cookies'),
        'use_strict_mode'         => ini_on('session.use_strict_mode'),
        'serialize_handler'       => ini_get('session.serialize_handler'),
        'memory_limit'            => ini_get('memory_limit'),
        'post_max_size'           => ini_get('post_max_size'),
    ],
    'mitigations_applied' => [
        'upload_progress_off' => !ini_on('session.upload_progress.enabled'),
        'cookies_only'        => ini_on('session.use_only_cookies'),
        'strict_mode'         => ini_on('session.use_strict_mode'),
    ],
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
