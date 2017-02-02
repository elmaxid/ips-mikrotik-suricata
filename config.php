<?php
header( 'Content-Type: text/plain' );
$user_name    = "xxxxxxx";
/* Database username */
$password     = "xxxxxxxx";
/* Database password */
$database     = "snorby";
$server       = "localhost";
$PID_app_file = '/tmp/ips_mikrotik.pid';
$PID_reload_file = '/tmp/ips_mikrotik_reload.pid'; //para recargar las reglas


$cfg[ 'whitelist' ] = '10.10.';

$router['ip']="10.20.20.1"; //ip
$router['user']="apixxx"; // user login
$router['pass']="api123";  //pass
?>