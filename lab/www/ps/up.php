<?php
session_save_path('/var/lib/php/sessions');
session_start();
echo "producer ok (handler=" . ini_get('session.serialize_handler') . ")";
