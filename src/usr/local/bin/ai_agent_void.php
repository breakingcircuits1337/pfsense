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
        // Ensure our config file exists
        if (!file_exists($this->void_conf)) touch($this->void_conf);
        $this->ensure_config_inclusion();
    }

    private function ensure_config_inclusion() {
        // Automatically add include directive to pfSense unbound custom options if missing
        global $config;
        $changed = false;

        // Initialize if missing
        if (!isset($config['unbound']['custom_options'])) {
            $config['unbound']['custom_options'] = "";
        }

        $include_directive = "include: \"{$this->void_conf}\"";
        $opts = $config['unbound']['custom_options'];

        // Check for base64
        if (base64_encode(base64_decode($opts, true)) === $opts) {
             $opts = base64_decode($opts);
             $was_encoded = true;
        } else {
             $was_encoded = false;
        }

        if (strpos($opts, $this->void_conf) === false) {
            $this->log("Adding include directive to Unbound config...");
            // pfSense Unbound custom options usually need 'server:' prefix if not already present,
            // but often the UI wraps it. However, 'include:' must be inside 'server:'.
            // We check if 'server:' block is implicit or explicit.
            // Safest bet is to append it.

            $opts .= "\nserver:{$include_directive}\n";

            if ($was_encoded) {
                $config['unbound']['custom_options'] = base64_encode($opts);
            } else {
                $config['unbound']['custom_options'] = $opts;
            }

            write_config("The Void Agent: Added include for $this->void_conf");
            $changed = true;
        }

        if ($changed) {
            // Trigger Unbound resync/restart to apply main config change
            // In a real environment: services_unbound_configure();
            // Here we simulate via reload if the file is generated, but writing config.xml ensures persistence on reboot.
            $this->log("Unbound config updated. Reloading...");
            mwexec("/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload");
        }
    }

    public function observe() {
        if (!file_exists($this->log_file)) return;

        // Tail the log safely (last 50 lines)
        $cmd = "tail -n 50 " . escapeshellarg($this->log_file);
        exec($cmd, $lines);

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
