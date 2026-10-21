<?php
echo "before:".memory_get_usage()."\n";
$x = $_POST['a'] ?? '(none)';
echo "len:".strlen($x)."\n";
