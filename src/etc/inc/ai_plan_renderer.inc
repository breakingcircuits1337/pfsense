<?php
/**
 * AIPlanRenderer: Renders human-friendly previews of AI-generated configuration change proposals.
 *
 * Schema for operation items:
 * - type (string): e.g., firewall_rule_add, nat_rule_add, alias_add, vlan_create, dhcp_pool_set, interface_assign, openvpn_server_add, shaper_rule_add, block_country_alias_add, rule_anchor_note
 * - path (string): config path hint (e.g., "filter/rule[+]/...")
 * - value (array): values to set/create
 * - note (string): optional human note
 */

class AIPlanRenderer
{
    /**
     * Render a human-readable preview and diff-like summary for a proposal.
     *
     * @param array $proposal Proposal structure with keys:
     *    - operations (array): List of operations as per schema
     *    - impacts (array): Description of intended effects
     *    - risk_warnings (array): List of risk warnings
     *    - explanation (string): Human summary of intent
     * @return array
     *    - text (string): Human-readable summary
     *    - diff (string): Diff-like representation of operations
     *    - impacts (array)
     *    - risk_warnings (array)
     */
    public static function render_preview(array $proposal): array
    {
        $counts = [
            'firewall_rule_add' => 0,
            'nat_rule_add' => 0,
            'alias_add' => 0,
            'vlan_create' => 0,
            'dhcp_pool_set' => 0,
            'interface_assign' => 0,
            'openvpn_server_add' => 0,
            'shaper_rule_add' => 0,
            'block_country_alias_add' => 0,
            'rule_anchor_note' => 0,
            '_other' => 0,
        ];
        $diff_lines = [];
        if (!isset($proposal['operations']) || !is_array($proposal['operations'])) {
            $proposal['operations'] = [];
        }
        foreach ($proposal['operations'] as $op) {
            $type = $op['type'] ?? 'unknown';
            if (isset($counts[$type])) {
                $counts[$type]++;
            } else {
                $counts['_other']++;
            }
        }

        // Header summary
        $header = [];
        if ($counts['firewall_rule_add']) $header[] = "{$counts['firewall_rule_add']} firewall rule" . ($counts['firewall_rule_add'] > 1 ? "s" : "");
        if ($counts['nat_rule_add']) $header[] = "{$counts['nat_rule_add']} NAT rule" . ($counts['nat_rule_add'] > 1 ? "s" : "");
        if ($counts['alias_add'] || $counts['block_country_alias_add']) {
            $alias_sum = $counts['alias_add'] + $counts['block_country_alias_add'];
            $header[] = "{$alias_sum} alias" . ($alias_sum > 1 ? "es" : "");
        }
        if ($counts['vlan_create']) $header[] = "{$counts['vlan_create']} VLAN" . ($counts['vlan_create'] > 1 ? "s" : "");
        if ($counts['dhcp_pool_set']) $header[] = "{$counts['dhcp_pool_set']} DHCP pool" . ($counts['dhcp_pool_set'] > 1 ? "s" : "");
        if ($counts['interface_assign']) $header[] = "{$counts['interface_assign']} interface assignment" . ($counts['interface_assign'] > 1 ? "s" : "");
        if ($counts['openvpn_server_add']) $header[] = "{$counts['openvpn_server_add']} OpenVPN server";
        if ($counts['shaper_rule_add']) $header[] = "{$counts['shaper_rule_add']} shaper rule" . ($counts['shaper_rule_add'] > 1 ? "s" : "");
        if ($counts['_other']) $header[] = "{$counts['_other']} additional item" . ($counts['_other'] > 1 ? "s" : "");
        if ($counts['rule_anchor_note']) $header[] = "{$counts['rule_anchor_note']} note" . ($counts['rule_anchor_note'] > 1 ? "s" : "");

        $headerstr = $header ? "This will add " . implode(", ", $header) . "." : "This will make changes as described below.";
        $caution = "No changes will be applied until confirmed and applied through the appropriate workflow.";

        // Explanation at the top
        $text = trim(($proposal['explanation'] ?? '')) . "\n\n" . $headerstr . " " . $caution;

        // Render diff lines
        foreach ($proposal['operations'] as $op) {
            $type = $op['type'] ?? 'unknown';
            $path = $op['path'] ?? '';
            $value = $op['value'] ?? [];
            $note = $op['note'] ?? '';
            $summary = "+ {$type}";
            if ($path) {
                $summary .= " @ $path";
            }
            if (!empty($value)) {
                $summary .= ": " . json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
            }
            if ($note) {
                $summary .= " // " . $note;
            }
            $diff_lines[] = $summary;
        }

        $diff = implode("\n", $diff_lines);

        return [
            'text' => $text,
            'diff' => $diff,
            'impacts' => $proposal['impacts'] ?? [],
            'risk_warnings' => $proposal['risk_warnings'] ?? [],
        ];
    }
}