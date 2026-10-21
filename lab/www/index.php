<?php
// php-oom-corruption-lab lab landing page. Intentionally vulnerable demo app.
// DO NOT deploy on anything reachable from an untrusted network.
?><!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>php-oom-corruption-lab lab</title></head>
<body style="font-family:system-ui;max-width:48rem;margin:3rem auto">
<h1>php-oom-corruption-lab lab</h1>
<p>Deliberately-vulnerable <code>PHP <?= PHP_VERSION ?></code>
   (<?= PHP_SAPI ?>). For CVE-2026-109618 / CVE-2026-109619 research only.</p>
<ul>
  <li><a href="/info.php">/info.php</a> - machine-readable condition report (JSON)</li>
  <li><a href="/session_probe.php">/session_probe.php</a> - session read/write demonstrator</li>
</ul>
</body></html>
