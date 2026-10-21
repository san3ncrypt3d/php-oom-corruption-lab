<?php
// Deliberately vulnerable demo endpoint. Lab use only.

class DestructProbe {
    public $marker = 'default';
    public function __destruct() {
        @file_put_contents(sys_get_temp_dir() . '/destruct_marker.log',
            date('c') . " DestructProbe::__destruct fired marker=" . $this->marker . "\n", FILE_APPEND);
    }
}

// Common gadget shape: a cache/view writer that flushes buffered content to a
// path on destruction. Instantiating one via session object-injection gives
// arbitrary file write -> RCE, no file-inclusion bug required.
class CacheFlush {
    public $cacheFile = null;
    public $html = '';
    public function __destruct() {
        if ($this->cacheFile) @file_put_contents($this->cacheFile, $this->html);
    }
}

session_save_path('/var/lib/php/sessions');
session_start();

$action = $_GET['action'] ?? 'show';
header('Content-Type: application/json');

if ($action === 'seed') {
    $_SESSION['note'] = $_GET['note'] ?? 'hello';
    echo json_encode(['stored' => $_SESSION, 'session_id' => session_id()]);
    exit;
}

echo json_encode([
    'session_id' => session_id(),
    'contents'   => array_map(fn($v) => is_object($v) ? get_class($v) . ' (object)' : $v, $_SESSION),
    'marker_log' => @file_get_contents(sys_get_temp_dir() . '/destruct_marker.log') ?: '(no destruct yet)',
]);
