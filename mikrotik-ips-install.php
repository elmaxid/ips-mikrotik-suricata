<?php


/*****************************
 *
 * IPS MikroTik Suricata
 *
 * This script install the schema to MYSQL DB
 * 
 * Author: Maximiliano Dobladez info@mkesolutions.net
 *
 * http://maxid.com.ar | http://www.mkesolutions.net  
 *
 * for API MIKROTIK:
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class
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
require( 'share/routeros_api.php' );
$API = new RouterosAPI();
require 'config.php';
/* Wait for a connection to the database */
$db_ = new mysqli( $server, $user_name, $password, $database );
if ( $db_->connect_errno > 0 )
    die( 'Unable to connect to database [' . $db_->connect_error . ']' );
echo "Connect OK - DB MySQL\n";
if ( isset( $router[ 'ip' ] ) ) {
    try {
        $API->connect( $router[ 'ip' ], $router[ 'user' ], $router[ 'pass' ] );
    }
    catch ( Exception $e ) {
        die( 'Unable to connect to RouterOS. Error:' . $e );
    }
    echo "Connect OK - API MikroTik RouterOS\n";
} //isset( $router[ 'ip' ] )
$SQL_DB = "              DROP TABLE IF EXISTS `block_queue`;";
if ( !$result = $db_->query( $SQL_DB ) ) {
    die( 'There was an error running the query [' . $db_->error . ']' );
} //!$result = $db_->query( $SQL_DB )
$SQL_DB = " 
                    CREATE TABLE `block_queue` (
                      `que_id` int(11) NOT NULL AUTO_INCREMENT,
                      `que_added` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT 'When the block was added',
                      `que_ip_adr` varchar(64) COLLATE utf8_unicode_ci NOT NULL COMMENT 'The IP address to block',
                      `que_timeout` varchar(12) COLLATE utf8_unicode_ci NOT NULL COMMENT 'How long to block for',
                      `que_sig_name` varchar(256) COLLATE utf8_unicode_ci NOT NULL COMMENT 'The name of the signature that caused the block',
                      `que_sig_gid` int(10) NOT NULL COMMENT 'The signature group ID',
                      `que_sig_sid` int(10) NOT NULL COMMENT 'The signature ID',
                      `que_event_timestamp` timestamp NOT NULL DEFAULT '0000-00-00 00:00:00' COMMENT 'When the event was triggered',
                      `que_processed` int(11) NOT NULL DEFAULT '0' COMMENT 'If this item has been processed (0=no, <>0=yes)',
                      PRIMARY KEY (`que_id`),
                      KEY `que_added` (`que_added`)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='Queue of ip addresses to block on firewall';";
if ( !$result = $db_->query( $SQL_DB ) ) {
    die( 'There was an error running the query [' . $db_->error . ']' );
} //!$result = $db_->query( $SQL_DB )
$SQL_DB = "                     DROP TABLE IF EXISTS `sigs_to_block`;";
if ( !$result = $db_->query( $SQL_DB ) ) {
    die( 'There was an error running the query [' . $db_->error . ']' );
} //!$result = $db_->query( $SQL_DB )
$SQL_DB = " 
                    CREATE TABLE `sigs_to_block` (
                      `sig_name` text COLLATE utf8_unicode_ci NOT NULL,
                      `src_or_dst` char(3) COLLATE utf8_unicode_ci NOT NULL DEFAULT 'src',
                      `timeout` varchar(12) COLLATE utf8_unicode_ci NOT NULL DEFAULT '01:00:00',
                      UNIQUE KEY `sig_name_unique_index` (`sig_name`(64))
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;";
if ( !$result = $db_->query( $SQL_DB ) ) {
    die( 'There was an error running the query [' . $db_->error . ']' );
} //!$result = $db_->query( $SQL_DB )
$SQL_DB = " 
                    INSERT INTO `sigs_to_block` (`sig_name`, `src_or_dst`, `timeout`) VALUES
                    ('ET COMPROMISED Known Compromised or Hostile Host Traffic',    'src',  '01:00:00'),
                    ('ET POLICY Suspicious inbound to', 'src',  '01:00:00'),
                    ('ET DROP Dshield Block Listed Source', 'src',  '01:00:00'),
                    ('ET SCAN Sipvicious Scan', 'src',  '01:00:00'),
                    ('ET SCAN Sipvicious User-Agent Detected (friendly-scanner)',   'src',  '01:00:00'),
                    ('ET DROP Spamhaus DROP Listed Traffic Inbound',    'src',  '01:00:00'),
                    ('ET POLICY Outgoing Basic Auth Base64 HTTP Password detected unencrypted', 'dst',  '23:59:59'),
                    ('ET CINS Active Threat Intelligence Poor Reputation IP',   'src',  '01:00:00'),
                    ('GPL SNMP public access udp',  'src',  '01:00:00'),
                    ('ET TOR Known Tor Relay/Router (Not Exit) Node Traffic',   'src',  '01:00:00'),
                    ('GPL DNS named version attempt',   'src',  '01:00:00'),
                    ('ET VOIP Modified Sipvicious Asterisk PBX User-Agent', 'src',  '01:00:00'),
                    ('GPL RPC xdmcp info query',    'src',  '01:00:00'),
                    ('GPL RPC portmap listing UDP 111', 'src',  '01:00:00'),
                    ('GPL ATTACK_RESPONSE id check returned root',  'src',  '00:01:10'),
                    ('ET VOIP Multiple Unauthorized SIP Responses UDP', 'dst',  '00:59:59'),
                    ('ET POLICY Suspicious inbound to mySQL port 3306', 'src',  '00:10:00'),
                    ('ET SCAN Behavioral Unusually fast Terminal Server Traffic, Potential Scan or Infection (Inbound)',    'src',  '00:10:00'),
                    ('ET DOS Possible NTP DDoS Inbound Frequent',   'src',  '00:10:00'),
                    ('ET SCAN SipCLI VOIP Scan',    'src',  '01:00:00'); ";
if ( !$result = $db_->query( $SQL_DB ) ) {
    die( 'There was an error running the query [' . $db_->error . ']' );
} //!$result = $db_->query( $SQL_DB )
echo "Create Schema MySQL OK \n";
$db_->close();
$API->disconnect();
?>