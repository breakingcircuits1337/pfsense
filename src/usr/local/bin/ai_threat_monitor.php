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
    '/var/log/snort/alert',
    '/var/log/ai_honeypot.log'
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
$event_memory = []; // [ip => ['score' => float, 'last_seen' => int, 'events' => []]]
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
    $target_ip = null;

    foreach ($ips as $ip) {
        if (!is_public($ip)) continue;

        // Cleanup old memory
        if (isset($event_memory[$ip]) && (time() - $event_memory[$ip]['last_seen'] > 3600)) {
            unset($event_memory[$ip]);
        }

        // Simple cache for exact duplicates to avoid spamming AI on burst logs
        if (isset($ip_cache[$ip]) && (time() - $ip_cache[$ip] < 10)) continue;

        $needs_scan = true;
        $target_ip = $ip; // Focus on the first actionable public IP
        break;
    }

    if (!$needs_scan || !$target_ip) continue;

    // Update simple cache
    $ip_cache[$target_ip] = time();

    // Send to AI with context
    $context = isset($event_memory[$target_ip]) ? $event_memory[$target_ip]['events'] : [];
    $analysis = analyze_log_line($line, $context);

    if ($analysis && isset($analysis['attacker_ip']) && $analysis['attacker_ip'] === $target_ip) {
        $score = floatval($analysis['threat_score'] ?? 0);
        $reason = $analysis['reason'] ?? 'Detected suspicious activity';

        // Initialize memory if needed
        if (!isset($event_memory[$target_ip])) {
            $event_memory[$target_ip] = ['score' => 0, 'last_seen' => time(), 'events' => []];
        }

        // Update memory
        $event_memory[$target_ip]['score'] += $score;
        $event_memory[$target_ip]['last_seen'] = time();
        $event_memory[$target_ip]['events'][] = date('H:i:s') . ": " . $reason;

        // Cap events history
        if (count($event_memory[$target_ip]['events']) > 5) {
            array_shift($event_memory[$target_ip]['events']);
        }

        // Decision logic
        $accumulated_score = $event_memory[$target_ip]['score'];
        $global_threshold = floatval($config['system']['ai']['monitor']['threshold'] ?? 0.7);

        // Immediate block if single event is high confidence, or accumulated score breaches threshold
        if (($score >= $global_threshold) || ($accumulated_score >= ($global_threshold * 1.5))) {
             if (strpos($line, $target_ip) !== false) {
                 $block_reason = "Accumulated Risk Score: " . $accumulated_score . ". Last: " . $reason;
                 block_ip($target_ip, $block_reason);
                 unset($event_memory[$target_ip]); // Clear memory after block
             }
        }

        // Check for other playbooks (e.g. alert only)
        if (isset($analysis['suggested_action'])) {
            $act = $analysis['suggested_action'];
            if ($act === 'alert_admin') {
                // Example: Send notification to system log or email (simulated here via logger)
                exec("/usr/bin/logger -p local0.notice " . escapeshellarg("AI Alert for $target_ip: $reason"));
            }
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

function analyze_log_line($line, $context_events = []) {
    global $config;
    $conf = $config['system']['ai'] ?? [];
    if (empty($conf['monitor']['enable'])) return null;

    $provider_name = $conf['default_provider'] ?? 'gemini';
    $threshold = floatval($conf['monitor']['threshold'] ?? 0.7);
    $shodan_key = $conf['shodan']['apikey'] ?? '';
    $abuse_key = $conf['abuseipdb']['apikey'] ?? '';

    // Exponential backoff for API calls
    $attempts = 0;
    $max_attempts = 3;
    $backoff = 1;

    while ($attempts < $max_attempts) {
        try {
            $provider = AIProviderFactory::make($provider_name);
            $system = "You are a firewall security AI. Analyze the log line. Extract the ATTACKER IP. " .
                      "Return JSON: { \"attacker_ip\": \"1.2.3.4\" (or null), \"threat_score\": 0.0-1.0, \"reason\": \"...\", \"suggested_action\": \"block\"|\"alert_admin\"|\"none\" } " .
                      "Consider previous events if provided.";

            $msg = "Current Log: $line\n";
            if (!empty($context_events)) {
                $msg .= "Previous Events for suspected IP:\n" . implode("\n", $context_events) . "\n";
            }

            // Extract potential IP to query Threat Intel
            if (preg_match('/(?<![\d.])(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?![\d.])/', $line, $m)) {
                $attacker_ip = $m[0];
                if (is_public($attacker_ip)) {
                    // Shodan
                    if (!empty($shodan_key)) {
                        $shodan_info = shodan_lookup($attacker_ip, $shodan_key);
                        if ($shodan_info) $msg .= "\n\nShodan Context: " . $shodan_info;
                    }
                    // AbuseIPDB
                    if (!empty($abuse_key)) {
                        $abuse_info = abuseipdb_check($attacker_ip, $abuse_key);
                        if ($abuse_info) $msg .= "\n\nAbuseIPDB Context: " . $abuse_info;
                    }
                }
            }

            $res = $provider->send_chat([$system, $msg]);

            // Extract JSON
            $json_start = strpos($res, '{');
            $json_end = strrpos($res, '}');
            if ($json_start !== false && $json_end !== false) {
                $json_str = substr($res, $json_start, $json_end - $json_start + 1);
                $data = json_decode($json_str, true);
                if ($data && isset($data['threat_score'])) {
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

function shodan_lookup($ip, $key) {
    $url = "https://api.shodan.io/shodan/host/{$ip}?key={$key}&minify=true";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3); // Fast timeout to not block too long
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 200 && $resp) {
        $data = json_decode($resp, true);
        if ($data) {
            $ports = implode(", ", $data['ports'] ?? []);
            $tags = implode(", ", $data['tags'] ?? []);
            $org = $data['org'] ?? 'Unknown';
            return "Organization: $org. Open Ports: $ports. Tags: $tags.";
        }
    }
    return null;
}

function abuseipdb_check($ip, $key) {
    $url = "https://api.abuseipdb.com/api/v2/check?ipAddress=" . urlencode($ip) . "&maxAgeInDays=90";
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 3);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        "Key: $key",
        "Accept: application/json"
    ]);
    $resp = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($code === 200 && $resp) {
        $data = json_decode($resp, true);
        if ($data && isset($data['data'])) {
            $score = $data['data']['abuseConfidenceScore'] ?? 0;
            $reports = $data['data']['totalReports'] ?? 0;
            return "AbuseIPDB Score: $score/100. Total Reports: $reports.";
        }
    }
    return null;
}
?>
