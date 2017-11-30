-- master thesis syslog
-- by Tom Petersen
-- plugin_id: 9042

DELETE FROM plugin WHERE id = "9042";
DELETE FROM plugin_sid WHERE plugin_id = "9042";

-- Plugin-Konfiguration
INSERT IGNORE INTO plugin (id, type, name, description) 
VALUES (9042, 1, 'master_thesis_syslog', 'A plugin to receive syslog events during my master thesis');

-- Konfiguration einzelner plugin_sid-Eintraege fuer verschiedene Events
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability, priority, name) 
VALUES (9042, 1, NULL, NULL, 2, 2, 'Room entered');
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, class_id, reliability, priority, name) 
VALUES (9042, 2, NULL, NULL, 3, 3, 'Room left');