<?php

/*****************************
 *
 * IPS MikroTik Suricata
 *
 * This script is the daemon to clean DB
 * 
 * Author: Maximiliano Dobladez info@mkesolutions.net
 *
 * http://maxid.com.ar | http://www.mkesolutions.net  
 *
 * for API MIKROTIK:
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class
 *
 * Inspired on: http://forum.mikrotik.com/viewtopic.php?t=111727
 *
 * LICENSE: GPLv2 GNU GENERAL PUBLIC LICENSE
 *
 * v1.1 - 10 Feb 17 - add support telegram, multiple whitelist,
 * v1.0 - 2 Feb 17 - initial version
 ******************************/


$DEBUG = false;
// $DEBUG=true;
if ( !$DEBUG )
    error_reporting( 0 );
require( 'share/routeros_api.php' );
$API = new RouterosAPI();
require 'functions.php';
require 'config.php';

/* Wait for a connection to the database */
$i                  = 0;
while ( $i < 100 ) {
    $db_ = new mysqli( $server, $user_name, $password, $database );
    if ( $db_->connect_errno > 0 ) {
        print( 'Unable to connect to database [' . $db_->connect_error . ']' );
        sleep( 10 );
        $i = $i + 10;
    } //$db_->connect_errno > 0
    else {
        $i = 100;
        touch( $PID_app_file );
    }
} //$i < 100
while ( file_exists( $PID_app_file ) ) {
    $SQL = "SELECT *,inet_ntoa(que_ip_adr) as ip FROM block_queue WHERE que_processed = 0 LIMIT 10;";
    if ( !$result = $db_->query( $SQL ) ) {
        die( 'There was an error running the query [' . $db_->error . ']' );
    } //!$result = $db_->query( $SQL )
    while ( $row = $result->fetch_assoc() ) {
        // if ( strpos( $row[ 'que_ip_adr' ], $cfg[ 'whitelist' ] ) !== true ) {
        if (!   array_search_partial($cfg[ 'whitelist' ],$row[ 'ip' ])) {
            /* Does not match local address... */
            try {
                $API->connect( $router['ip'], $router['user'], $router['pass'] );
            }
            catch ( Exception $e ) {
                die( 'Unable to connect to RouterOS. Error:' . $e );
            }
            /* Now add the address into the Blocked address-list group */
            $comment_tmp="From suricata, " . $row[ 'que_sig_name' ] . " => " . $row[ 'que_sig_gid' ] . ":" . $row[ 'que_sig_sid' ] . " => event timestamp: " . $row[ 'que_event_timestamp' ] ;
            $API->comm( "/ip/firewall/address-list/add", array(
                 "list" => "Blocked",
                "address" => $row[ 'ip' ],
                "timeout" => $row[ 'que_timeout' ],
                "comment" => $comment_tmp
            ) );
            $API->disconnect();
            //si esta activo el api de telegram, avisar
            if ($active_api_telegram) {
                $comment_tmp.=" => IP: ".$row['ip'] . " => Timeout: ".$row[ 'que_timeout' ];
                send_to_telegram($comment_tmp);
            }
            //si esta activo el mail envio por correo el alerta
            if ($active_mail_report) {
                    /* Send email indicating bad block attempt*/
                    $to      = 'noreply@gmail.com';
                    $subject = 'Suricata on snort-host: attempted block on local address';
                    $message = 'A record in the block_queue indicated a block on a local IP Address (' . $row[ 'ip' ] . ")\r\n";
                    $message = $message . "\r\n";
                    $message = $message . "The signature ID is " . $row[ 'que_sig_id' ] . " named: " . $row[ 'que_sig_name' ] . "\r\n";
                    $message = $message . "    with a que_id of " . $row[ 'que_id' ] . "\r\n\r\n";
                    $message = $message . "Check the src_or_dst field in events_to_block for the signature to make sure it is correct (src/dst).\r\n\r\n";
                    $message = $message . "The record was not processed but marked as completed.\r\n";
                    $headers = 'From: noreply@gmail.com' . "\r\n" . 'Reply-To: noreply@gmail.com' . "\r\n" . 'X-Mailer: PHP/' . phpversion();
                    // mail($to, $subject, $message, $headers);                
            }
        }  
        else {
          // echo "Exception";
        }
        $SQL2 = "UPDATE block_queue set que_processed = 1 WHERE que_id = " . $row[ 'que_id' ] . ";";
        if ( !$result2 = $db_->query( $SQL2 ) ) {
            die( 'There was an error running the query [' . $db_->error . ']' );
        } //!$result2 = $db_->query( $SQL2 )
        mysqli_free_result( $result2 );
    } //eof while
    mysqli_free_result( $result );
    sleep( 2 );
    /* Sleep 2 seconds then do again */
    mysqli_ping( $db_ );
} //file_exists( $PID_app_file )
echo "Shutdown services cron\n";
unlink( $PID_app_file );
$db_->close();

?>