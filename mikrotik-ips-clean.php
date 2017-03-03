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
 * v1.2 - 3 March 17 - This script mikrotik-ips-daemon_db.php is depreceated because now we use trigger on DB
 * v1.1 - 10 Feb 17 - add support telegram, multiple whitelist,
 * v1.0 - 2 Feb 17 - initial version
 ******************************/


$DEBUG = false;
// $DEBUG=true;
if ( !$DEBUG )
    error_reporting( 0 );
require 'functions.php';
require 'config.php';
/* Wait for a connection to the database */
$i = 0;
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
    // Borra los bloqueos procesados que tenga como fecha la hora de agregado mas el timeout para eliminarlo y que se vuelva a agregar luego 
    $SQL = "DELETE FROM block_queue WHERE  que_processed=1 AND (que_added + INTERVAL que_timeout HOUR_SECOND) <= NOW()  ;";
    if ( !$result = $db_->query( $SQL ) ) {
        die( 'There was an error running the query [' . $db_->error . ']' );
    } //!$result = $db_->query( $SQL )
    mysqli_free_result( $result );
    sleep( 10 );
    /* Sleep 10 seconds then do again */
    mysqli_ping( $db_ );
} //file_exists( $PID_app_file )
echo "Shutdown services Clean DB\n";
unlink( $PID_app_file );
$db_->close();
?>