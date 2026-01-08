#!/usr/local/bin/php
<?php
/*
 * ai_agent_warden.php
 * "The Warden" - Identity & VPN Overseer
 * Monitors VPN and Auth logs for Impossible Travel and hijacked sessions.
 */

require_once("/etc/inc/agents.inc");
require_once("/etc/inc/util.inc");

class WardenAgent extends AIAgent {
    private $auth_log = '/var/log/auth.log';
    private $vpn_log = '/var/log/openvpn.log';

    // Max reasonable travel speed in km/h (approx airliner speed)
    private $max_speed = 900;

    public function __construct() {
        parent::__construct("Warden", "The bouncer. Monitor VPN/Auth logs for Impossible Travel and hijacked sessions.");
    }

    public function observe() {
        $logins = [];

        // Check SSH/Web Auth Logs
        if (file_exists($this->auth_log)) {
            $cmd = "tail -n 50 " . escapeshellarg($this->auth_log);
            exec($cmd, $lines);
            foreach ($lines as $line) {
                // Example: ... successful login for user 'alice' from: 1.2.3.4
                // Adjust regex for standard BSD auth.log formats (sshd, php-fpm)
                if (preg_match('/successful login for user \'?(\w+)\'? from:? (\d+\.\d+\.\d+\.\d+)/i', $line, $m) ||
                    preg_match('/Accepted publickey for (\w+) from (\d+\.\d+\.\d+\.\d+)/', $line, $m)) {
                    $logins[] = ['user' => $m[1], 'ip' => $m[2], 'ts' => time()]; // In real impl, parse date from line
                }
            }
        }

        // Check OpenVPN Logs
        if (file_exists($this->vpn_log)) {
            $cmd = "tail -n 50 " . escapeshellarg($this->vpn_log);
            exec($cmd, $lines);
            foreach ($lines as $line) {
                // Example: ... user 'bob' authenticated from 5.6.7.8 ...
                if (preg_match('/user \'(\w+)\' authenticated from (\d+\.\d+\.\d+\.\d+)/i', $line, $m)) {
                    $logins[] = ['user' => $m[1], 'ip' => $m[2], 'ts' => time()];
                }
            }
        }

        // De-duplicate and process
        foreach ($logins as $login) {
            $user = $login['user'];
            $ip = $login['ip'];

            // Skip local IPs
            if (!$this->is_public($ip)) continue;

            // Update memory with pending analysis if it's a new login event we haven't processed
            // (Simple de-dupe logic: check if last login for user was same IP and < 5 mins ago)
            $last = $this->memory['users'][$user] ?? null;
            if ($last && $last['ip'] === $ip && (time() - $last['ts'] < 300)) {
                continue;
            }

            $this->memory['pending_logins'][] = $login;
        }
    }

    public function analyze() {
        $pending = $this->memory['pending_logins'] ?? [];
        if (empty($pending)) return;

        foreach ($pending as $login) {
            $user = $login['user'];
            $ip = $login['ip'];
            $ts = $login['ts'];

            // GeoIP Lookup
            $geo = $this->get_geoip($ip);
            if (!$geo) continue;

            // Check history
            if (isset($this->memory['users'][$user])) {
                $prev = $this->memory['users'][$user];

                // If IP changed, check travel
                if ($prev['ip'] !== $ip) {
                    $distance = $this->calculate_distance($prev['lat'], $prev['lon'], $geo['lat'], $geo['lon']);
                    $time_diff = $ts - $prev['ts'];

                    // Avoid division by zero
                    if ($time_diff <= 0) $time_diff = 1;

                    $speed = ($distance / ($time_diff / 3600)); // km per hour

                    if ($speed > $this->max_speed) {
                        $reason = "Impossible Travel detected. User '$user' moved {$distance}km in {$time_diff}s (Speed: " . round($speed) . "km/h). From {$prev['country']} to {$geo['country']}.";

                        // Ask AI for confirmation/context
                        $decision = $this->ask_ai(
                            "Analyze this login anomaly. User logged in from two distant locations in a short time. Is this impossible travel or potentially valid (e.g. VPN usage)? Return JSON: {\"verdict\": \"malicious\"|\"safe\", \"reason\": \"...\"}",
                            $reason
                        );

                        $json = $this->extract_json($decision);
                        if ($json && $json['verdict'] === 'malicious') {
                            $this->memory['threats'][] = ['user' => $user, 'ip' => $ip, 'reason' => $json['reason']];
                        }
                    }
                }
            }

            // Update User State
            $this->memory['users'][$user] = [
                'ip' => $ip,
                'ts' => $ts,
                'lat' => $geo['lat'],
                'lon' => $geo['lon'],
                'country' => $geo['country']
            ];
        }

        $this->memory['pending_logins'] = [];
    }

    public function act() {
        if (!empty($this->memory['threats'])) {
            foreach ($this->memory['threats'] as $threat) {
                $this->log("Blocking User/IP: " . json_encode($threat));

                // Action 1: Block IP
                mwexec("/sbin/pfctl -t ai_blocklist -T add " . escapeshellarg($threat['ip']));

                // Action 2: Kill States for that user/IP (simulated)
                // mwexec("/sbin/pfctl -k " . escapeshellarg($threat['ip']));

                // Notify System
                $msg = "AI Warden: Blocked {$threat['user']} from {$threat['ip']}. Reason: {$threat['reason']}";
                exec("/usr/bin/logger -p auth.crit " . escapeshellarg($msg));
            }
            $this->memory['threats'] = [];
        }
    }

    private function is_public($ip) {
        if (substr($ip, 0, 4) === '127.') return false;
        if (substr($ip, 0, 3) === '10.') return false;
        if (substr($ip, 0, 8) === '192.168.') return false;
        return true;
    }

    private function get_geoip($ip) {
        // Simple caching wrapper for ip-api.com
        if (isset($this->memory['geoip_cache'][$ip])) {
            return $this->memory['geoip_cache'][$ip];
        }

        // Use stream context with timeout
        $ctx = stream_context_create(['http' => ['timeout' => 3]]);
        $json = @file_get_contents("http://ip-api.com/json/$ip?fields=status,country,lat,lon", false, $ctx);

        if ($json) {
            $data = json_decode($json, true);
            if ($data && $data['status'] === 'success') {
                $res = ['lat' => $data['lat'], 'lon' => $data['lon'], 'country' => $data['country']];
                $this->memory['geoip_cache'][$ip] = $res;
                return $res;
            }
        }
        return null;
    }

    private function calculate_distance($lat1, $lon1, $lat2, $lon2) {
        // Haversine formula
        $r = 6371; // Earth radius km
        $dLat = deg2rad($lat2 - $lat1);
        $dLon = deg2rad($lon2 - $lon1);
        $a = sin($dLat/2) * sin($dLat/2) +
             cos(deg2rad($lat1)) * cos(deg2rad($lat2)) *
             sin($dLon/2) * sin($dLon/2);
        $c = 2 * atan2(sqrt($a), sqrt(1-$a));
        return $r * $c;
    }

    private function extract_json($text) {
        if (preg_match('/\{.*\}/s', $text, $matches)) {
            return json_decode($matches[0], true);
        }
        return null;
    }
}

// Daemon Run Loop
$agent = new WardenAgent();
echo "Starting The Warden...\n";
while (true) {
    $agent->run_cycle();
    sleep(60); // Check every minute
}
?>
