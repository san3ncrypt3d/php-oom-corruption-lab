<?php
$elems = [];
for ($i = 0; $i < 64*1024; $i++) { $elems[] = "i:$i;N;"; }
$payload = 'O:13:"SplFixedArray":' . count($elems) . ':{' . implode('', $elems) . '}';
$pad = str_repeat('a', max(10*1024*1024 - memory_get_usage(true) - 512*1024, 1));
unserialize($payload);
echo "survived\n";
