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
// require('routeros_api.class.php');
require 'functions.php';
require 'config.php';
/* Wait for a connection to the database */
$i = 0;
while ( $i < 100 ) {
    $db = new mysqli( $server, $user_name, $password, $database );
    if ( $db->connect_errno > 0 ) {
        print( 'Unable to connect to database [' . $db->connect_error . ']' );
        sleep( 10 );
        $i = $i + 10;
    } //$db->connect_errno > 0
    else {
        $i = 100;
        touch( $PID_app_file );
        touch( $PID_reload_file );
    }
} //$i < 100
$ARRAY_sig_to_block = get_signature(); //get the signatures to block
 if ( $DEBUG ) echo var_dump($ARRAY_sig_to_block);
//init_id
// $id_events          = 0;//demo
$id_events          = get_last_event(); // obtiene el ultimo id
while ( file_exists( $PID_app_file ) ) {
    if ( !file_exists( $PID_reload_file ) ) {
        $ARRAY_sig_to_block = get_signature(); //get the signatures to block 
        touch( $PID_reload_file );
        echo "\nReload Rules. Loading ".count($ARRAY_sig_to_block)."\n";
    } //!file_exists( $PID_reload_file )
    // while ( 1==1 ) {
    $SQL = "SELECT  *,inet_ntoa(ip_src) as src ,inet_ntoa(ip_dst) as dst FROM events_with_join  WHERE id > $id_events and timestamp >= DATE_SUB(NOW(),INTERVAL 1 HOUR)  
      ORDER by timestamp asc
      LIMIT 1000;";
    // $SQL = "SELECT  *,inet_ntoa(ip_src) as src ,inet_ntoa(ip_dst) as dst FROM events_with_join WHERE id > $id_events and timestamp >= DATE_SUB(NOW(),INTERVAL 1 HOUR)  LIMIT 100;";
    if ( !$result = $db->query( $SQL ) ) {
        die( 'There was an error running the query [' . $db->error . ']' );
    } //!$result = $db->query( $SQL )
    while ( $row = $result->fetch_assoc() ) {
        unset( $key );
        unset( $msg_TXT );    
         if ( $DEBUG ) echo "\nSearching for : ".$row[ 'sig_name' ];

        $key = array_search_partial( array_column( $ARRAY_sig_to_block, 'sig_name' ), $row[ 'sig_name' ] );
        if ( $key ) {
              if ( $DEBUG ) echo "\nFounded it with key ".$key;
            // $msg_TXT= "From Suricata:  $row[sig_name] -> $row[sid]:$row[signature] -> event Timestamp: $row[timestamp] ->IP ".$ARRAY_sig_to_block[$key]['src_or_dst']." ntoa : ".$row['ip_'.$ARRAY_sig_to_block[$key]['src_or_dst']]." ". $row[$ARRAY_sig_to_block[$key]['src_or_dst']] . " -> Timeout: ".$ARRAY_sig_to_block[$key]['timeout'];
            $msg_TXT                            = get_text_to_report( $row, $ARRAY_sig_to_block[ $key ] );
            $sql_to_db[ 'que_ip_adr' ]          = $row[ 'ip_' . $ARRAY_sig_to_block[ $key ][ 'src_or_dst' ] ];
            $sql_to_db[ 'que_sig_name' ]        = $row[ sig_name ];
            $sql_to_db[ 'que_sig_sid' ]         = $row[ signature ];
            $sql_to_db[ 'que_timeout' ]         = $ARRAY_sig_to_block[ $key ][ 'timeout' ];
            $sql_to_db[ 'que_event_timestamp' ] = $row[ timestamp ];
            ;
            save_to_db_block( $sql_to_db );
            if ( $DEBUG )
                echo $msg_TXT . "\n";
        } //$key
        else {
             if ( $DEBUG ) echo "NO KEY FOUND \n";
        }
        $id_events = $row[ 'id' ]; //get the last id
        // mysqli_free_result($result2);
    } //$row = $result->fetch_assoc()
    mysqli_free_result( $result );
    /* Sleep 5 seconds then do again */
    sleep( 3 );
    /* Sleep 5 seconds then do again */
    mysqli_ping( $db );
} //file_exists( $PID_app_file )
echo "Shutdown services Daemon\n";
unlink( $PID_app_file );
$db->close();

?>