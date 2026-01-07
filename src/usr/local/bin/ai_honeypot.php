#!/usr/local/bin/php
<?php
/*
 * ai_honeypot.php
 * Lightweight AI Deception / Honeypot Listener
 * Binds to configured ports, simulates services via AI, and logs hits.
 */

ini_set("max_execution_time", "0");
require_once("/etc/inc/config.inc");
require_once("/etc/inc/util.inc");
require_once("/etc/inc/ai.inc");

// Configuration
$config_ai = $config['system']['ai'] ?? [];
$honeypot_ports = [21, 23, 8080]; // Default example ports if none in config
// In a real implementation, these would be configurable via UI

$log_file = '/var/log/ai_honeypot.log';

// Fork listener for each port
$pids = [];

foreach ($honeypot_ports as $port) {
    $pid = pcntl_fork();
    if ($pid == -1) {
        die("Could not fork worker for port $port");
    } else if ($pid) {
        // Parent
        $pids[] = $pid;
    } else {
        // Child
        run_listener($port, $log_file, $config_ai);
        exit(0);
    }
}

// Parent waits
foreach ($pids as $pid) {
    pcntl_waitpid($pid, $status);
}

function run_listener($port, $log_file, $conf) {
    $socket = socket_create(AF_INET, SOCK_STREAM, SOL_TCP);
    if (!socket_bind($socket, '0.0.0.0', $port)) {
        syslog(LOG_ERR, "Honeypot: Could not bind port $port");
        return;
    }
    socket_listen($socket);

    // Default banners
    $banner = "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"; // Fake SSH/Telnet
    if ($port == 80 || $port == 8080) {
        $banner = "HTTP/1.1 200 OK\r\nServer: Apache/2.4.41 (Ubuntu)\r\n\r\n<html><body>It works!</body></html>";
    }

    while (true) {
        $client = @socket_accept($socket);
        if ($client) {
            socket_getpeername($client, $ip);

            // Log the hit immediately
            $msg = date('M d H:i:s') . " HONEYPOT_HIT: IP $ip connected to port $port";
            file_put_contents($log_file, $msg . "\n", FILE_APPEND);

            // Send fake banner
            socket_write($client, $banner);

            // Optional: Read some input to feed to AI later?
            // $input = socket_read($client, 1024);

            socket_close($client);
        }
    }
}
?>
