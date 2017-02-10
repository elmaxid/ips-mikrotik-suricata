<?php
// header( 'Content-Type: text/plain' );
/* Database username */
$user_name    = "xxxxxxx";
/* Database password */
$password     = "xxxxxxxxxx";
$database     = "snorby";
$server       = "localhost";
$PID_app_file = '/tmp/ips_mikrotik.pid';
$PID_reload_file = '/tmp/ips_mikrotik_reload.pid'; //para recargar las reglas



// TELEGRAM API
$url_api_telegram="https://api.telegram.org/botXXXXXXXX:XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX/sendMessage?chat_id=XXXXXXXXXXX&text=";
$active_api_telegram=false; //true para funcionar

//mail report
$active_mail_report=false;

$cfg[ 'whitelist' ] = array('10.10.','192.168.','172.16','1.1.1.'); //whiteliist ,'82.165.177.154'

$router['ip']="10.200.200.1"; //IP Router
$router['user']="xxxx"; // user login
$router['pass']="xxxxxx";  //pass
?>