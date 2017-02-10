<?php


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
        if ( strpos( $keyword , $string) !== FALSE )   return $index;
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


/**
 * [send_to_telegram Envia el Alerta por Telegram]
 * @param  [type] $text [description]
 * @return [type]       [description]
 */
function send_to_telegram($text) {
        global   $url_api_telegram;  
    $fetch=file_get_contents($url_api_telegram.$text);
    // echo $fetch;
   $ret_fetch=json_decode($fetch,true);
    // echo var_dump($ret_fetch);
   if ($ret_fetch[ok]) {
        // echo "Enviado con exito";
        return true;
   }
  
}

?>