#!/usr/local/bin/php
<?php
/*
 * ai_threat_monitor.php
 * Background daemon for AI Intelligent Defender
 * Watches logs and uses configured LLM to detect and block threats.
 */

ini_set("max_execution_time", "0");

require_once("/etc/inc/config.inc");
require_once("/etc/inc/util.inc");
require_once("/etc/inc/ai.inc");

// Ensure we don't run multiple instances
$pidfile = "/var/run/ai_threat_monitor.pid";
if (file_exists($pidfile)) {
    $pid = trim(file_get_contents($pidfile));
    if (is_numeric($pid) && posix_kill($pid, 0)) {
        die("AI Threat Monitor is already running (PID $pid)\n");
    }
}
file_put_contents($pidfile, getmypid());

// Signal handling
if (function_exists('pcntl_async_signals')) {
    pcntl_async_signals(true);
    pcntl_signal(SIGTERM, 'signal_handler');
    pcntl_signal(SIGINT, 'signal_handler');
}

$running = true;
function signal_handler($signo) {
    global $running;
    $running = false;
}

// Log files to monitor
$logs = [
    '/var/log/filter.log',
    '/var/log/suricata/eve.json',
    '/var/log/snort/alert'
];

$valid_logs = [];
foreach ($logs as $l) {
    if (file_exists($l)) $valid_logs[] = $l;
}

if (empty($valid_logs)) {
    echo "No logs found. Waiting...\n";
    sleep(10);
    foreach ($logs as $l) { if (file_exists($l)) $valid_logs[] = $l; }
    if (empty($valid_logs)) {
        echo "Still no logs. Exiting.\n";
        @unlink($pidfile);
        exit(0);
    }
}

echo "Starting AI Threat Monitor on: " . implode(", ", $valid_logs) . "\n";

// Open pipe to tail
$cmd = "tail -n 0 -F " . implode(" ", array_map('escapeshellarg', $valid_logs));
$handle = popen($cmd, "r");

$ip_cache = []; // [ip => timestamp]
$events_log = '/var/db/ai_events.log';
$blocklist_file = '/var/db/ai_blocklist.json';

while ($running && !feof($handle)) {
    $line = fgets($handle);
    if ($line === false) break;
    $line = trim($line);
    if (empty($line)) continue;

    // Quick parse for IP to check cache
    $ips = [];
    // Enhanced regex to match IPv4 addresses more accurately, excluding some common version number patterns
    // Matches 4 groups of 1-3 digits separated by dots, surrounded by non-digit/dot characters or start/end of line
    if (preg_match_all('/(?<![\d.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![\d.])/', $line, $matches)) {
        $ips = $matches[0];
    }

    if (empty($ips)) continue;

    // If we found IPs, check if we need to scan
    $needs_scan = false;
    foreach ($ips as $ip) {
        if (!is_public($ip)) continue;
        if (isset($ip_cache[$ip]) && (time() - $ip_cache[$ip] < 3600)) continue;
        $needs_scan = true;
        break;
    }

    if (!$needs_scan) continue;

    // Send to AI
    $analysis = analyze_log_line($line);

    // Update cache for all IPs in the line so we don't spam for same packet
    foreach ($ips as $ip) {
        $ip_cache[$ip] = time();
    }

    if ($analysis && isset($analysis['action']) && $analysis['action'] === 'block' && !empty($analysis['attacker_ip'])) {
        $attacker = $analysis['attacker_ip'];
        // Validate attacker is in the line (sanity check)
        if (strpos($line, $attacker) !== false && is_public($attacker)) {
             block_ip($attacker, $analysis['reason'] ?? 'AI Detected Threat');
        }
    }
}

pclose($handle);
@unlink($pidfile);

function is_public($ip) {
    // Basic filter
    if (substr($ip, 0, 4) === '127.') return false;
    if (substr($ip, 0, 3) === '10.') return false;
    if (substr($ip, 0, 8) === '192.168.') return false;
    // ... more RFC1918 can be added
    return true;
}

function analyze_log_line($line) {
    global $config;
    $conf = $config['system']['ai'] ?? [];
    if (empty($conf['monitor']['enable'])) return null;

    $provider_name = $conf['default_provider'] ?? 'gemini';
    $threshold = floatval($conf['monitor']['threshold'] ?? 0.7);

    // Exponential backoff for API calls
    $attempts = 0;
    $max_attempts = 3;
    $backoff = 1;

    while ($attempts < $max_attempts) {
        try {
            $provider = AIProviderFactory::make($provider_name);
            $system = "You are a firewall security AI. Analyze the log line. Extract the ATTACKER IP. Return JSON: { \"attacker_ip\": \"1.2.3.4\" (or null), \"threat_score\": 0.0-1.0, \"action\": \"block\"|\"ignore\", \"reason\": \"...\" }";
            $msg = "Log: $line";

            $res = $provider->send_chat([$system, $msg]);

            // Extract JSON
            $json_start = strpos($res, '{');
            $json_end = strrpos($res, '}');
            if ($json_start !== false && $json_end !== false) {
                $json_str = substr($res, $json_start, $json_end - $json_start + 1);
                $data = json_decode($json_str, true);
                if ($data && isset($data['threat_score']) && $data['threat_score'] >= $threshold) {
                    return $data;
                }
            }
            return null; // Success but no threat detected or invalid JSON
        } catch (Exception $e) {
            $attempts++;
            if ($attempts >= $max_attempts) {
                 syslog(LOG_ERR, "AI Monitor: Failed to contact $provider_name after $attempts attempts: " . $e->getMessage());
                 return null;
            }
            sleep($backoff);
            $backoff *= 2;
        }
    }
    return null;
}

function block_ip($ip, $reason) {
    global $events_log, $blocklist_file;
    // Add to pf table
    exec("/sbin/pfctl -t ai_blocklist -T add " . escapeshellarg($ip));

    $entry = [
        'type' => 'block',
        'ip' => $ip,
        'reason' => $reason,
        'timestamp' => time()
    ];

    // Append to events log
    file_put_contents($events_log, json_encode($entry) . "\n", FILE_APPEND);

    // Update blocklist json
    $list = [];
    if (file_exists($blocklist_file)) {
        $list = json_decode(file_get_contents($blocklist_file), true);
        if (!is_array($list)) $list = [];
    }
    $list[$ip] = ['reason' => $reason, 'time' => time()];
    file_put_contents($blocklist_file, json_encode($list));
}
?>
