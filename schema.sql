



USE snorby;

SET foreign_key_checks = 0;
-- DROP TABLE `block_queue`, `sigs_to_block`;
#  DROP TRIGGER `after_iphdr_insert`;
#  
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
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci COMMENT='Queue of ip addresses to block on firewall';



   CREATE TABLE `sigs_to_block` (
                      `sig_name` text COLLATE utf8_unicode_ci NOT NULL,
                      `src_or_dst` char(3) COLLATE utf8_unicode_ci NOT NULL DEFAULT 'src',
                      `timeout` varchar(12) COLLATE utf8_unicode_ci NOT NULL DEFAULT '01:00:00',
                      UNIQUE KEY `sig_name_unique_index` (`sig_name`(64))
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;


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
                    ('ET SCAN SipCLI VOIP Scan',    'src',  '01:00:00');


                      DELIMITER ;;
                      CREATE TRIGGER `after_iphdr_insert` AFTER INSERT ON `iphdr` FOR EACH ROW
                      BEGIN
                        DECLARE this_event INT(11) default 0;
                        DECLARE this_event_signature INT(10) default 0;
                        DECLARE this_event_timestamp TIMESTAMP;
                        DECLARE this_sig INT(10) default 0;
                        DECLARE this_sig_name VARCHAR(256) default "";
                        DECLARE this_sig_gid INT(10) default 0;
                        DECLARE timeout VARCHAR(12) default "";
                        DECLARE interested INT default 0;
                        DECLARE direction VARCHAR(3) default "";
                        DECLARE ip_src VARCHAR(64) default "";
                        DECLARE ip_dst VARCHAR(64) default "";
                        SELECT event.id, event.signature, event.timestamp
                        INTO this_event, this_event_signature, this_event_timestamp
                        FROM event
                        WHERE event.sid = NEW.sid and event.cid = NEW.cid;  
                        SELECT signature.sig_sid, signature.sig_gid, signature.sig_name 
                        INTO this_sig, this_sig_gid, this_sig_name
                        FROM signature
                        WHERE signature.sig_id = this_event_signature;
                        SELECT count(*), sigs_to_block.src_or_dst, sigs_to_block.timeout
                        INTO interested, direction, timeout
                        FROM sigs_to_block
                        WHERE this_sig_name LIKE CONCAT(sigs_to_block.sig_name, '%');
                        IF (interested > 0) THEN
                         IF (direction = "src") THEN
                            INSERT INTO block_queue
                         SET que_ip_adr =NEW.ip_src,
                                que_timeout = timeout,
                                que_sig_name = this_sig_name,
                                que_sig_gid = this_sig_gid,
                                que_sig_sid = this_sig,
                                que_event_timestamp = this_event_timestamp;
                          ELSE
                            INSERT INTO block_queue
                         SET que_ip_adr =NEW.ip_dst,
                                que_timeout = timeout,
                                que_sig_name = this_sig_name,
                                que_sig_gid = this_sig_gid,
                                que_sig_sid = this_sig,
                                que_event_timestamp = this_event_timestamp;
                          END IF;
                        END IF;
                      END;;
                      DELIMITER ;

