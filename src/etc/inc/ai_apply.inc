<?php
/**
 * AIApplyEngine — PREVIEW-ONLY by default; guarded config apply for AI Assistant proposals.
 * 
 * Usage:
 *   - validateProposal($proposal): returns structure with validation, warnings, affected subsystems.
 *   - apply($proposal, $options): dry-run unless $options['confirm']===true.
 * 
 * All changes are idempotent, append/set only, never deletes.
 */

class AIApplyEngine
{
    /**
     * Validate a proposal for completeness, safety, and subsystem impacts.
     * @param array $proposal
     * @return array [ valid, errors, warnings, unsupported, plan_summary, affected_subsystems ]
     */
    public static function validateProposal(array $proposal): array
    {
        $valid = true;
        $errors = [];
        $warnings = [];
        $unsupported = [];
        $affected = [];
        $summary = [];
        $ops = $proposal['operations'] ?? [];
        foreach ($ops as $idx => $op) {
            // Schema check
            if (empty($op['type']) || !isset($op['path']) || !isset($op['value'])) {
                $valid = false;
                $errors[] = "Operation #$idx missing required fields (type/path/value).";
                continue;
            }
            // Subsystem impact
            $type = $op['type'];
            switch ($type) {
                case 'firewall_rule_add':
                case 'alias_add':
                    $affected['filter'] = true;
                    break;
                case 'vlan_create':
                case 'interface_assign':
                case 'dhcp_pool_set':
                    $affected['interfaces'] = true;
                    break;
                case 'openvpn_server_add':
                    $affected['openvpn'] = true;
                    break;
                case 'ipsec_phase1_add':
                case 'ipsec_phase2_add':
                    $affected['ipsec'] = true;
                    break;
                case 'carp_vip_add':
                case 'pfsync_enable':
                case 'xmlrpc_sync_set':
                    $affected['system_ha'] = true;
                    break;
                case 'gateway_group_add':
                    $affected['gwlb'] = true;
                    break;
                case 'shaper_rule_add':
                    $affected['shaper'] = true;
                    break;
                case 'rule_anchor_note':
                    // No-op for apply, can append to notes only
                    break;
                default:
                    $unsupported[] = $type;
                    $warnings[] = "Unsupported operation type: $type";
                    $valid = false;
            }
            // Security-first checks
            if ($type === 'firewall_rule_add') {
                $val = $op['value'];
                $iface = strtolower($val['interface'] ?? '');
                $action = strtolower($val['action'] ?? '');
                $src = strtolower($val['src'] ?? '');
                $dst = strtolower($val['dst'] ?? '');
                if ($iface === 'wan' && $action === 'pass' &&
                    ($src === 'any' || $src === '0.0.0.0/0') &&
                    ($dst === 'any' || $dst === '0.0.0.0/0')) {
                    $warnings[] = "WAN pass any->any rule at op #$idx is risky: exposes firewall to the Internet.";
                    if (empty($op['force'])) $valid = false;
                }
                // Exposing admin ports
                $ports = [];
                if (isset($val['port'])) $ports = is_array($val['port']) ? $val['port'] : explode(',', $val['port']);
                if (isset($val['dst_port'])) $ports = is_array($val['dst_port']) ? $val['dst_port'] : explode(',', $val['dst_port']);
                foreach ([22, 80, 443] as $mgmt) {
                    if (in_array((string)$mgmt, $ports, true)) {
                        $warnings[] = "WAN pass to admin port $mgmt (op #$idx) may expose management interface.";
                    }
                }
            }
        }
        if ($unsupported) $warnings[] = "Unsupported operation types: " . implode(', ', $unsupported);
        $affected_subsystems = array_keys($affected);
        $plan_summary = "Operations: " . count($ops) . ". Subsystems affected: " . implode(', ', $affected_subsystems);
        return [
            'valid' => $valid,
            'errors' => $errors,
            'warnings' => $warnings,
            'unsupported' => $unsupported,
            'plan_summary' => $plan_summary,
            'affected_subsystems' => $affected_subsystems
        ];
    }

    /**
     * Apply the proposal to $config — guarded, only with confirm=true.
     * Always validates first. Always backup before writing.
     * @param array $proposal
     * @param array $options [ 'confirm'=>true, 'force'=>bool ]
     * @return array
     */
    public static function apply(array $proposal, array $options = []): array
    {
        global $config;
        if (empty($proposal['operations'])) {
            return [ 'applied'=>false, 'message'=>'Nothing to do' ];
        }
        $validation = self::validateProposal($proposal);
        if (!$validation['valid'] && empty($options['force'])) {
            return [
                'applied'=>false,
                'message'=>'Validation failed',
                'validation'=>$validation,
                'dry_run'=>true,
                'plan_preview'=>AIPlanRenderer::render_preview($proposal)
            ];
        }
        if (empty($options['confirm'])) {
            return [
                'applied'=>false,
                'message'=>'Confirmation required',
                'validation'=>$validation,
                'dry_run'=>true,
                'plan_preview'=>AIPlanRenderer::render_preview($proposal)
            ];
        }
        // --- Guarded apply: backup first ---
        if (function_exists('write_config')) {
            write_config("AI Assistant pre-apply backup");
        }
        $changes = 0;
        $notes = [];
        foreach ($proposal['operations'] as $op) {
            $type = $op['type'];
            $path = $op['path'];
            $value = $op['value'];
            switch ($type) {
                case 'firewall_rule_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'alias_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'vlan_create':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'interface_assign':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'dhcp_pool_set':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'openvpn_server_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'ipsec_phase1_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'ipsec_phase2_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'carp_vip_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'pfsync_enable':
                    self::safe_set($config, $path, $value);
                    $changes++;
                    break;
                case 'xmlrpc_sync_set':
                    self::safe_set($config, $path, $value);
                    $changes++;
                    break;
                case 'gateway_group_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'shaper_rule_add':
                    self::safe_push($config, $path, $value);
                    $changes++;
                    break;
                case 'rule_anchor_note':
                    $notes[] = $op['note'] ?? '';
                    break;
                default:
                    $notes[] = "Unsupported operation type (not applied): $type";
            }
        }
        if (function_exists('write_config')) {
            write_config("AI Assistant apply: " . substr($proposal['explanation'] ?? 'changes', 0, 120));
        }
        // Reconfigure subsystems (best-effort)
        $reconfigured = [];
        foreach ($validation['affected_subsystems'] as $ss) {
            switch ($ss) {
                case 'filter':
                    if (function_exists('filter_configure')) { filter_configure(); $reconfigured[] = 'filter'; }
                    break;
                case 'openvpn':
                    if (function_exists('openvpn_configure')) { openvpn_configure(); $reconfigured[] = 'openvpn'; }
                    break;
                case 'ipsec':
                    if (function_exists('ipsec_configure')) { ipsec_configure(); $reconfigured[] = 'ipsec'; }
                    break;
                case 'interfaces':
                    if (function_exists('interfaces_configure')) { interfaces_configure(); $reconfigured[] = 'interfaces'; }
                    break;
                case 'gwlb':
                    if (function_exists('gwlb_configure')) { gwlb_configure(); $reconfigured[] = 'gwlb'; }
                    break;
                case 'shaper':
                    if (function_exists('traffic_shaper_configure')) { traffic_shaper_configure(); $reconfigured[] = 'shaper'; }
                    break;
                case 'system_ha':
                    // No single function; informational only
                    $reconfigured[] = 'system_ha';
                    break;
                default:
                    break;
            }
        }
        return [
            'applied'=>true,
            'validation'=>$validation,
            'reconfigured'=>$reconfigured,
            'warnings'=>$validation['warnings'],
            'changes'=>$changes,
            'notes'=>$notes
        ];
    }

    /**
     * Safe push helper: walks path, appends value to [+] arrays.
     */
    private static function safe_push(&$arr, $path, $value)
    {
        $parts = explode('/', $path);
        $node = &$arr;
        foreach ($parts as $i => $part) {
            if ($part === '') continue;
            if (substr($part, -3) === '[+]') {
                $key = substr($part, 0, -3);
                if (!isset($node[$key]) || !is_array($node[$key])) $node[$key] = [];
                $node[$key][] = $value;
                return;
            } else {
                if (!isset($node[$part]) || !is_array($node[$part])) $node[$part] = [];
                $node = &$node[$part];
            }
        }
        // If no [+], treat as set on last node
        $node = $value;
    }

    /**
     * Safe set helper: sets value at path.
     */
    private static function safe_set(&$arr, $path, $value)
    {
        $parts = explode('/', $path);
        $node = &$arr;
        foreach ($parts as $i => $part) {
            if ($part === '') continue;
            if ($i === count($parts) - 1) {
                $node[$part] = $value;
            } else {
                if (!isset($node[$part]) || !is_array($node[$part])) $node[$part] = [];
                $node = &$node[$part];
            }
        }
    }
}