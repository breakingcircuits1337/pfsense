<?php
/**
 * AIRuleAnalyzer — pfSense AI-powered configuration analyzer.
 * 
 * SECURITY WARNING: This class is strictly PREVIEW-ONLY. 
 * It NEVER writes or modifies $config or system state.
 * All suggestions are for review, not for direct application.
 * 
 * Usage: AIRuleAnalyzer::analyze() and AIRuleAnalyzer::renderReport().
 */

class AIRuleAnalyzer
{
    /**
     * Analyze firewall/NAT rules for issues.
     * @param array $options
     * @return array Structured findings, summary, and metrics.
     */
    public static function analyze(array $options = []): array
    {
        global $config;
        $findings = [];
        $metrics = [
            'total_rules' => 0,
            'wan_pass_any_any' => 0,
            'duplicates' => 0,
            'shadowed' => 0,
            'exposed_services' => 0,
        ];

        $rules = (is_array($config['filter']['rule'])) ? $config['filter']['rule'] : [];
        $nat_rules = (is_array($config['nat']['rule'])) ? $config['nat']['rule'] : [];
        $outbound_nat = (is_array($config['nat']['outbound']['rule'])) ? $config['nat']['outbound']['rule'] : [];
        $ifaces = (is_array($config['interfaces'])) ? $config['interfaces'] : [];

        $metrics['total_rules'] = count($rules);

        // Shadowed rules
        $shadowed = self::detectShadowedFirewallRules($rules);
        foreach ($shadowed as $item) {
            $findings[] = [
                'id' => 'shadowed_rule_' . $item['idx'],
                'severity' => 'high',
                'description' => $item['desc'],
                'rationale' => "Rules below a broad allow are effectively disabled — this can be a critical security risk.",
                'impacted_paths' => [$item['path']],
                'suggested_operations' => [[
                    'op' => 'move_rule',
                    'rule_idx' => $item['idx'],
                    'details' => 'Consider reordering or tightening allow rule.'
                ]]
            ];
            $metrics['shadowed']++;
        }

        // Redundant/duplicate rules
        $redundant = self::detectRedundantRules($rules);
        foreach ($redundant as $item) {
            $findings[] = [
                'id' => 'redundant_rule_' . $item['idx'],
                'severity' => 'medium',
                'description' => $item['desc'],
                'rationale' => "Duplicate rules cause confusion and increase maintenance complexity.",
                'impacted_paths' => [$item['path']],
                'suggested_operations' => [[
                    'op' => 'disable_rule',
                    'rule_idx' => $item['idx'],
                    'details' => 'Consider disabling or removing redundant rule.'
                ]]
            ];
            $metrics['duplicates']++;
        }

        // Too-permissive WAN rules
        $too_permissive = self::detectTooPermissiveWAN($rules, $ifaces);
        foreach ($too_permissive as $item) {
            $findings[] = [
                'id' => 'wan_pass_any_' . $item['idx'],
                'severity' => 'critical',
                'description' => $item['desc'],
                'rationale' => "Allowing any source from WAN or exposing management ports is a major security risk.",
                'impacted_paths' => [$item['path']],
                'suggested_operations' => [[
                    'op' => 'tighten_rule',
                    'rule_idx' => $item['idx'],
                    'details' => 'Restrict src/dst or block management ports from WAN.'
                ]]
            ];
            $metrics['wan_pass_any_any']++;
        }

        // Exposed services via NAT
        $exposed = self::detectExposedServices($nat_rules, $rules);
        foreach ($exposed as $item) {
            $findings[] = [
                'id' => 'exposed_nat_' . $item['idx'],
                'severity' => 'high',
                'description' => $item['desc'],
                'rationale' => "Inbound NAT exposing admin ports or internal hosts is a risk unless properly allowlisted.",
                'impacted_paths' => [$item['path']],
                'suggested_operations' => [[
                    'op' => 'restrict_nat',
                    'nat_idx' => $item['idx'],
                    'details' => 'Limit source addresses or use allowlisting.'
                ]]
            ];
            $metrics['exposed_services']++;
        }

        // Outbound NAT overlaps
        $overlaps = self::detectOutboundNATOverlaps($outbound_nat);
        foreach ($overlaps as $item) {
            $findings[] = [
                'id' => 'outbound_nat_overlap_' . $item['idx'],
                'severity' => 'medium',
                'description' => $item['desc'],
                'rationale' => "Overlapping outbound NAT rules add complexity and may cause unexpected behavior.",
                'impacted_paths' => $item['paths'],
                'suggested_operations' => [[
                    'op' => 'consolidate_nat',
                    'rule_indices' => $item['indices'],
                    'details' => 'Consider consolidating overlapping outbound NAT rules.'
                ]]
            ];
        }

        // Summary
        $summary = "Analyzed " . $metrics['total_rules'] . " firewall rules.";
        if ($metrics['wan_pass_any_any'] > 0) {
            $summary .= " {$metrics['wan_pass_any_any']} WAN any-any pass rules detected.";
        }
        if ($metrics['duplicates'] > 0) {
            $summary .= " {$metrics['duplicates']} duplicate rules found.";
        }
        if ($metrics['shadowed'] > 0) {
            $summary .= " {$metrics['shadowed']} shadowed rules.";
        }
        if ($metrics['exposed_services'] > 0) {
            $summary .= " {$metrics['exposed_services']} exposed NAT/service findings.";
        }
        if (empty($findings)) {
            $summary .= " No critical findings.";
        }

        return [
            'findings' => $findings,
            'summary' => $summary,
            'metrics' => $metrics
        ];
    }

    /**
     * Render a human-friendly report and AIPlanRenderer-style diff.
     * @param array $analysis
     * @return array
     */
    public static function renderReport(array $analysis): array
    {
        $text = $analysis['summary'] . "\n";
        foreach ($analysis['findings'] as $f) {
            $sev = strtoupper($f['severity']);
            $text .= "- [{$sev}] {$f['description']} (Rationale: {$f['rationale']})\n";
        }
        // Extract suggested operations for diff
        $diff = [];
        foreach ($analysis['findings'] as $f) {
            foreach ($f['suggested_operations'] as $op) {
                $diff[] = $op;
            }
        }
        return [
            'text' => $text,
            'diff' => $diff,
            'counts' => $analysis['metrics'],
        ];
    }

    /** --------- PRIVATE HELPERS --------- */

    /**
     * Detects shadowed rules: broad allow above block or narrower deny.
     * @param array $rules
     * @return array of ['idx', 'desc', 'path']
     */
    private static function detectShadowedFirewallRules(array $rules): array
    {
        $findings = [];
        // Simple heuristic: allow any above block
        for ($i = 0; $i < count($rules) - 1; $i++) {
            $r = $rules[$i];
            if (isset($r['action'], $r['interface'], $r['source'], $r['destination'])
                && $r['action'] === 'pass'
                && self::isAny($r['source'])
                && self::isAny($r['destination'])) {
                // Check next rules below for block on same iface
                for ($j = $i + 1; $j < count($rules); $j++) {
                    $r2 = $rules[$j];
                    if (isset($r2['action'], $r2['interface'])
                        && $r2['action'] === 'block'
                        && $r2['interface'] === $r['interface']) {
                        $findings[] = [
                            'idx' => $j,
                            'desc' => "Rule #$j is shadowed by broad allow-any above on interface '{$r['interface']}'.",
                            'path' => "filter/rule/$j",
                        ];
                    }
                }
            }
        }
        return $findings;
    }

    /**
     * Detects duplicate/redundant rules (same action and match).
     * @param array $rules
     * @return array of ['idx', 'desc', 'path']
     */
    private static function detectRedundantRules(array $rules): array
    {
        $findings = [];
        $seen = [];
        foreach ($rules as $idx => $r) {
            $sig = md5(json_encode([
                $r['action'] ?? null,
                $r['interface'] ?? null,
                $r['ipprotocol'] ?? null,
                $r['protocol'] ?? null,
                $r['source'] ?? null,
                $r['destination'] ?? null,
                $r['dstport'] ?? null,
                $r['srcport'] ?? null,
            ]));
            if (isset($seen[$sig])) {
                $findings[] = [
                    'idx' => $idx,
                    'desc' => "Rule #$idx is redundant/duplicate of rule #{$seen[$sig]}.",
                    'path' => "filter/rule/$idx",
                ];
            } else {
                $seen[$sig] = $idx;
            }
        }
        return $findings;
    }

    /**
     * Detects WAN pass any-any rules, and open management ports.
     * @param array $rules
     * @param array $ifaces
     * @return array of ['idx', 'desc', 'path']
     */
    private static function detectTooPermissiveWAN(array $rules, array $ifaces): array
    {
        $findings = [];
        foreach ($rules as $idx => $r) {
            if (($r['action'] ?? '') !== 'pass' || ($r['interface'] ?? '') !== 'wan') {
                continue;
            }
            // Allow any-any
            if (self::isAny($r['source']) && self::isAny($r['destination'])) {
                $findings[] = [
                    'idx' => $idx,
                    'desc' => "WAN pass rule #$idx allows any source to any destination.",
                    'path' => "filter/rule/$idx",
                ];
            }
            // Management port exposure
            $dst_ports = [];
            if (isset($r['dstport'])) {
                $dst_ports = is_array($r['dstport']) ? $r['dstport'] : explode(',', $r['dstport']);
            }
            foreach ([22, 80, 443] as $mgmt) {
                if (in_array((string)$mgmt, $dst_ports, true) || (empty($dst_ports) && ($r['protocol'] ?? '') === 'tcp')) {
                    $findings[] = [
                        'idx' => $idx,
                        'desc' => "WAN pass rule #$idx allows access to management port {$mgmt}.",
                        'path' => "filter/rule/$idx",
                    ];
                }
            }
        }
        return $findings;
    }

    /**
     * Detects NAT port forwards exposing admin ports or non-allowlisted hosts.
     * @param array $nat
     * @param array $rules
     * @return array of ['idx', 'desc', 'path']
     */
    private static function detectExposedServices(array $nat, array $rules): array
    {
        $findings = [];
        foreach ($nat as $idx => $n) {
            // Only port forwards on WAN
            if (($n['interface'] ?? '') !== 'wan') continue;
            $dst_ports = [];
            if (isset($n['dstport'])) {
                $dst_ports = is_array($n['dstport']) ? $n['dstport'] : explode(',', $n['dstport']);
            }
            foreach ([22, 80, 443] as $mgmt) {
                if (in_array((string)$mgmt, $dst_ports, true)) {
                    $findings[] = [
                        'idx' => $idx,
                        'desc' => "NAT port forward #$idx exposes management port {$mgmt} from WAN.",
                        'path' => "nat/rule/$idx",
                    ];
                }
            }
        }
        return $findings;
    }

    /**
     * Detects overlapping outbound NAT rules.
     * @param array $outbound_nat
     * @return array of ['idx', 'desc', 'paths', 'indices']
     */
    private static function detectOutboundNATOverlaps(array $outbound_nat): array
    {
        $findings = [];
        // Simple overlap check: same interface and overlapping src/dst
        for ($i = 0; $i < count($outbound_nat) - 1; $i++) {
            $ri = $outbound_nat[$i];
            for ($j = $i + 1; $j < count($outbound_nat); $j++) {
                $rj = $outbound_nat[$j];
                if (
                    isset($ri['interface'], $rj['interface']) &&
                    $ri['interface'] === $rj['interface'] &&
                    self::rangesOverlap($ri['source'] ?? [], $rj['source'] ?? []) &&
                    self::rangesOverlap($ri['destination'] ?? [], $rj['destination'] ?? [])
                ) {
                    $findings[] = [
                        'idx' => $i,
                        'desc' => "Outbound NAT rule #$i overlaps with rule #$j on interface {$ri['interface']}.",
                        'paths' => ["nat/outbound/rule/$i", "nat/outbound/rule/$j"],
                        'indices' => [$i, $j],
                    ];
                }
            }
        }
        return $findings;
    }

    /** Utility: checks if a rule endpoint is "any" */
    private static function isAny($endpoint): bool
    {
        if (!is_array($endpoint)) {
            $endpoint = [$endpoint];
        }
        foreach ($endpoint as $v) {
            if ($v === 'any' || $v === '' || $v === null) return true;
        }
        return false;
    }

    /** Utility: checks if two sources/destinations overlap (very basic) */
    private static function rangesOverlap($a, $b): bool
    {
        // If either is any, treat as overlap
        if (self::isAny($a) || self::isAny($b)) return true;
        // If both are arrays, check intersection
        $arrA = is_array($a) ? $a : [$a];
        $arrB = is_array($b) ? $b : [$b];
        return count(array_intersect($arrA, $arrB)) > 0;
    }
}

// END OF FILE — AIRuleAnalyzer, PREVIEW-ONLY, NEVER WRITES TO CONFIG.