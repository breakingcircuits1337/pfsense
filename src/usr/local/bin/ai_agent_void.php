#!/usr/local/bin/php
<?php
/*
 * ai_agent_void.php
 * "The Void" - DNS & Content Filter
 * Monitors Unbound logs for DGA/malicious domains and sinkholes them.
 */

require_once("/etc/inc/agents.inc");
require_once("/etc/inc/util.inc");

class VoidAgent extends AIAgent {
    private $log_file = '/var/log/resolver.log';
    private $sinkhole_ip = '127.0.0.1'; // Default sinkhole
    private $unbound_conf = '/var/unbound/unbound.conf';
    // In pfSense, custom options often go to /var/unbound/pfb_dnsbl.conf or similar,
    // but for this agent we might append to a dedicated include file.
    private $void_conf = '/var/unbound/ai_void.conf';

    public function __construct() {
        parent::__construct("Void", "The silencer. DNS Sinkholing, Leak Detection, and Domain Hallucination checks.");
        // Ensure our config file exists and is included (simulation)
        if (!file_exists($this->void_conf)) touch($this->void_conf);
    }

    public function observe() {
        if (!file_exists($this->log_file)) return;

        // Tail the log (last 50 lines)
        // Format often: Jan 22 10:00:00 unbound[12345]: info: 192.168.1.100 example.com. A IN
        $lines = array_slice(file($this->log_file), -50);
        foreach ($lines as $line) {
            // Regex to extract domain from query log
            // Adjust regex based on actual Unbound log verbosity 2 format
            if (preg_match('/info:\s+\S+\s+(\S+)\.\s+[A-Z]+\s+IN/i', $line, $m)) {
                $domain = $m[1];
                if ($this->is_interesting($domain)) {
                    $this->memory['pending_domains'][$domain] = ($this->memory['pending_domains'][$domain] ?? 0) + 1;
                }
            }
        }
    }

    public function analyze() {
        $domains = $this->memory['pending_domains'] ?? [];
        if (empty($domains)) return;

        foreach ($domains as $domain => $count) {
            // Check cache
            if ($this->is_sinkholed($domain)) {
                unset($this->memory['pending_domains'][$domain]);
                continue;
            }

            // Shannon Entropy for DGA detection
            $entropy = $this->calculate_entropy($domain);

            // Heuristic: High entropy (>4.0) or very long random-looking string
            if ($entropy > 4.0 || (strlen($domain) > 20 && $entropy > 3.5)) {
                $decision = $this->ask_ai(
                    "Analyze this domain name for DGA (Domain Generation Algorithm) or malicious C2 patterns. Return JSON: {\"verdict\": \"malicious\"|\"safe\", \"confidence\": 0.0-1.0, \"reason\": \"...\"}",
                    "Domain: $domain. Entropy: $entropy. Query Count: $count."
                );

                $json = $this->extract_json($decision);
                if ($json && isset($json['verdict']) && $json['verdict'] === 'malicious' && $json['confidence'] > 0.8) {
                    $this->memory['sinkhole_targets'][$domain] = $json['reason'];
                } else {
                    // Cache as safe for a while?
                }
            }
            // Clear processed
            unset($this->memory['pending_domains'][$domain]);
        }
    }

    public function act() {
        if (empty($this->memory['sinkhole_targets'])) return;

        $new_entries = false;
        foreach ($this->memory['sinkhole_targets'] as $domain => $reason) {
            if (!$this->is_sinkholed($domain)) {
                $this->log("Sinkholing domain: $domain. Reason: $reason");
                $config_line = "local-zone: \"$domain\" redirect\nlocal-data: \"$domain A $this->sinkhole_ip\"\n";
                file_put_contents($this->void_conf, $config_line, FILE_APPEND);
                $new_entries = true;

                // Add to persistent blocklist memory
                $this->memory['blocked_domains'][$domain] = time();
            }
            unset($this->memory['sinkhole_targets'][$domain]);
        }

        if ($new_entries) {
            // Reload Unbound
            $this->log("Reloading Unbound DNS...");
            mwexec("/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload");
        }
    }

    private function is_interesting($domain) {
        // Whitelist common TLDs or local domains
        if (strpos($domain, 'local') !== false) return false;
        if (strpos($domain, 'arpa') !== false) return false;
        if (strpos($domain, 'google.com') !== false) return false;
        return true;
    }

    private function is_sinkholed($domain) {
        return isset($this->memory['blocked_domains'][$domain]);
    }

    private function calculate_entropy($string) {
        $h = 0;
        $size = strlen($string);
        foreach (count_chars($string, 1) as $v) {
            $p = $v / $size;
            $h -= $p * log($p) / log(2);
        }
        return $h;
    }

    private function extract_json($text) {
        if (preg_match('/\{.*\}/s', $text, $matches)) {
            return json_decode($matches[0], true);
        }
        return null;
    }
}

// Daemon Run Loop
$agent = new VoidAgent();
echo "Starting The Void...\n";
while (true) {
    $agent->run_cycle();
    sleep(60); // Check every minute
}
?>
