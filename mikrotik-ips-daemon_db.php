<?php

/*****************************
 *
 * IPS MikroTik Suricata
 *
 * This script is the daemon to search some alert and add it to block queue
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
 *
 * v1.0 - 2 Feb 17 - initial version
 ******************************/


$DEBUG = false;
// $DEBUG=true;
if ( !$DEBUG )
    error_reporting( 0 );
// require('routeros_api.class.php');
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
/**
 * [get_signature obtiene las firmas que se utilizaran para IPS]
 * @return [type] [description]
 */
function get_signature( ) {
    global $db;
    $SQL = "SELECT  sig_name,src_or_dst,timeout  FROM sigs_to_block LIMIT 100;"; //limit to 100 
    if ( !$result = $db->query( $SQL ) ) {
        die( 'There was an error running the query [' . $db->error . ']' );
    } //!$result = $db->query( $SQL )
    $i = 0;
    while ( $row = $result->fetch_assoc() ) {
        // echo var_dump($row);
        $ret[ $i ][ 'sig_name' ]   = $row[ 'sig_name' ];
        $ret[ $i ][ 'src_or_dst' ] = $row[ 'src_or_dst' ];
        $ret[ $i ][ 'timeout' ]    = $row[ 'timeout' ];
        $i++;
    } //$row = $result->fetch_assoc()
    mysqli_free_result( $result );
    return $ret;
}
/**
 * [save_to_db_block guarda en la DB el bloqueo si no existe el IP en la lista. El mantenimiento de la misma la realiza otro agente]
 * @param  [array] $array_to_db [array con los datos a guardar en DB]
 * @return [type]              [description]
 */
function save_to_db_block( $array_to_db = NULL ) {
    global $db;
    if ( !$array_to_db )
        return false;
    $sql = "INSERT INTO block_queue (que_ip_adr, que_sig_name, que_sig_sid,que_timeout,que_event_timestamp)
              SELECT * FROM (SELECT '$array_to_db[que_ip_adr]', '$array_to_db[que_sig_name]', '$array_to_db[que_sig_sid]','$array_to_db[que_timeout]','$array_to_db[que_event_timestamp]') AS tmp
        WHERE NOT EXISTS ( SELECT que_ip_adr FROM block_queue WHERE que_ip_adr = '$array_to_db[que_ip_adr]'  ) LIMIT 1;";
    // $sql="INSERT INTO block_queue (que_ip_adr, que_sig_name, que_sig_sid,que_timeout)
    //             SELECT * FROM (SELECT '$array_to_db[que_ip_adr]', '$array_to_db[que_sig_name]', '$array_to_db[que_sig_sid]','$array_to_db[que_timeout]') AS tmp 
    //      WHERE   (SELECT que_processed FROM block_queue WHERE que_ip_adr = '$array_to_db[que_ip_adr]' ) != 0";
    //  echo $sql;
    if ( !$result = $db->query( $sql ) ) {
        die( 'There was an error running the query [' . $db->error . ']' );
    } //!$result = $db->query( $sql )
    //    while($row = $result->fetch_assoc())  echo $row;
    //  mysqli_free_result($result);
}
/**
 * [get_text_to_report hace el formato de la linea de texto a agregar como comentario en el address list]
 * @param  [type] $row                [description]
 * @param  [type] $ARRAY_sig_to_block [description]
 * @return [type]                     [description]
 */
function get_text_to_report( $row, $ARRAY_sig_to_block ) {
    $msg_TXT = "From Suricata:  $row[sig_name] -> $row[sid]:$row[signature] -> event Timestamp: $row[timestamp] ->IP " . $ARRAY_sig_to_block[ 'src_or_dst' ] . " ntoa : " . $row[ 'ip_' . $ARRAY_sig_to_block[ 'src_or_dst' ] ] . " " . $row[ $ARRAY_sig_to_block[ 'src_or_dst' ] ] . " -> Timeout: " . $ARRAY_sig_to_block[ 'timeout' ];
    return $msg_TXT;
}
/**
 * [array_search_partial busca un string en un valor de un array y devuelve el key]
 * @param  [type] $arr     [description]
 * @param  [type] $keyword [description]
 * @return [type]          [description]
 */
function array_search_partial( $arr, $keyword ) {
      
    foreach ( $arr as $index => $string ) {
      
        if ( strpos( $keyword , $string) !== FALSE )
            return $index;
    } //$arr as $index => $string
}
/**
 * [get_last_event ontiene el ultimo valor del evento para empezar a buscar por nuevas incidencias]
 * @return [type] [description]
 */
function get_last_event( ) {
    global $db;
    $SQL = "SELECT  id  FROM events_with_join order by id desc LIMIT 1;"; // get the last event
    if ( !$result = $db->query( $SQL ) ) {
        die( 'There was an error running the query [' . $db->error . ']' );
    } //!$result = $db->query( $SQL )
    $i   = 0;
    $row = $result->fetch_assoc();
    mysqli_free_result( $result );
    return $row[ id ];
}
?>