<?php
/**
 * AIWizards — Conversational guided wizards for pfSense AI Assistant.
 * 
 * PREVIEW-ONLY: Generates proposals for HA, Multi-WAN, and VPN setup.
 * NEVER writes or applies changes to system config — all output is a preview.
 * All operation items conform to the schema:
 *   [ 'type' => string, 'path' => string, 'value' => array, 'note' => string? ]
 */

class AIWizards
{
    // List of supported types and their question sequences
    protected static $wizardQuestions = [
        'ha' => [
            'primary_hostname'   => 'What is the hostname of the primary firewall?',
            'secondary_hostname' => 'What is the hostname of the secondary firewall?',
            'wan_iface'          => 'Which interface is used for WAN?',
            'lan_iface'          => 'Which interface is used for LAN?',
            'vip_wan'            => 'Enter the WAN Virtual IP address (e.g. x.x.x.x/xx):',
            'vip_lan'            => 'Enter the LAN Virtual IP address (e.g. x.x.x.x/xx):',
            'vhids'              => 'Enter the VHID(s) to use (e.g. 1,2):',
            'carp_password'      => 'Enter the CARP password:',
            'pfsync_iface'       => 'Which interface will be used for pfsync?',
            'xmlrpc_peer_ip'     => 'Enter the XMLRPC sync peer IP:',
            'xmlrpc_password'    => 'Enter the XMLRPC sync password:',
        ],
        'multiwan' => [
            'wan_ifaces'     => 'List all WAN interfaces (comma separated, e.g. wan,wan2):',
            'mode'           => 'Select mode: failover or load-balance?',
            'weights'        => 'If load-balance, enter a weight per interface (comma separated, e.g. 1,2), or leave blank:',
            'monitor_ips'    => 'Enter a health check/monitor IP for each WAN (comma separated, e.g. 8.8.8.8,1.1.1.1):',
            'trigger_level'  => 'Select trigger level: packet-loss, latency, or both?',
        ],
        'vpn' => [
            'vpn_type'          => 'Which VPN type? (openvpn or ipsec)',
            // OpenVPN path
            'openvpn_port'      => 'Enter OpenVPN port (default 1194):',
            'openvpn_proto'     => 'Enter OpenVPN protocol (udp or tcp, default udp):',
            'openvpn_auth'      => 'OpenVPN auth type (cert, psk, userpass):',
            'openvpn_tun'       => 'Tunnel network (e.g. 10.10.10.0/24):',
            'openvpn_localnets' => 'Local networks to push (comma separated):',
            'openvpn_dns'       => 'DNS servers to push to clients (comma separated):',
            // IPsec path
            'ipsec_peer_ip'     => 'Remote IPsec peer IP:',
            'ipsec_auth'        => 'Auth type (psk or ikev2-cert):',
            'ipsec_phase1'      => 'Phase1 proposals (default: AES256/SHA256):',
            'ipsec_p1_lifetime' => 'Phase1 lifetime (seconds, default 28800):',
            'ipsec_p2_local'    => 'Phase2 local subnet(s) (comma separated):',
            'ipsec_p2_remote'   => 'Phase2 remote subnet(s) (comma separated):',
            'ipsec_p2_lifetime' => 'Phase2 lifetime (seconds, default 3600):',
        ],
    ];

    public static function start(string $type): array
    {
        $state = ['__step' => 0, '__answers' => [], '__branch' => null];
        $questions = self::getQuestions($type, $state);
        return ['questions' => $questions, 'state' => $state];
    }

    public static function next(string $type, array $state, array $answers): array
    {
        $step = $state['__step'] ?? 0;
        $collected = $state['__answers'] ?? [];
        $branch = $state['__branch'] ?? null;

        // Merge answers into collected state
        foreach ($answers as $k => $v) {
            $collected[$k] = $v;
        }

        // Wizard type-specific handling for step advancement and branch logic
        $questionKeys = self::getOrderedKeys($type, $collected, $branch);

        // Branching for VPN wizard after vpn_type
        if ($type === 'vpn' && $step === 0 && isset($collected['vpn_type'])) {
            $branch = strtolower(trim($collected['vpn_type'])) === 'ipsec' ? 'ipsec' : 'openvpn';
        }

        $nextStep = $step + count($answers);
        $state['__step'] = $nextStep;
        $state['__answers'] = $collected;
        $state['__branch'] = $branch;

        // Compute upcoming questions
        $remainingKeys = array_slice($questionKeys, $nextStep);
        if (!$remainingKeys) {
            return ['complete' => true, 'state' => $state];
        }
        $questions = [];
        foreach ($remainingKeys as $key) {
            // VPN branching logic
            if ($type === 'vpn' && $branch && strpos($key, $branch) !== 0) {
                continue;
            }
            // Only ask relevant fields for the chosen branch
            $questions[$key] = self::$wizardQuestions[$type][$key];
            break; // Ask one at a time
        }
        return ['questions' => $questions, 'state' => $state];
    }

    public static function buildProposal(string $type, array $state): array
    {
        // All proposals are strictly preview-only, non-destructive.
        $a = $state['__answers'] ?? [];
        $ops = [];
        $impacts = [];
        $risks = [];
        $explanation = '';

        switch ($type) {
            case 'ha':
                $vhids = array_map('trim', explode(',', $a['vhids'] ?? '1'));

                $ops[] = [
                    'type' => 'carp_vip_add',
                    'path' => 'interfaces/vips[+]',
                    'value' => [
                        'interface' => $a['wan_iface'] ?? '',
                        'subnet' => $a['vip_wan'] ?? '',
                        'vhid' => (int)($vhids[0] ?? 1),
                        'password' => '(provided)'
                    ],
                    'note' => 'Add CARP VIP on WAN'
                ];
                $ops[] = [
                    'type' => 'carp_vip_add',
                    'path' => 'interfaces/vips[+]',
                    'value' => [
                        'interface' => $a['lan_iface'] ?? '',
                        'subnet' => $a['vip_lan'] ?? '',
                        'vhid' => (int)($vhids[1] ?? 2),
                        'password' => '(provided)'
                    ],
                    'note' => 'Add CARP VIP on LAN'
                ];
                $ops[] = [
                    'type' => 'pfsync_enable',
                    'path' => 'system/pfsync',
                    'value' => [
                        'enable' => true,
                        'interface' => $a['pfsync_iface'] ?? ''
                    ],
                    'note' => 'Enable pfsync'
                ];
                $ops[] = [
                    'type' => 'xmlrpc_sync_set',
                    'path' => 'system/advanced/remote',
                    'value' => [
                        'peer_ip' => $a['xmlrpc_peer_ip'] ?? '',
                        'password' => '(provided)'
                    ],
                    'note' => 'Set XMLRPC sync peer'
                ];
                $ops[] = [
                    'type' => 'firewall_rule_add',
                    'path' => 'filter/rule[+]',
                    'value' => [
                        'interface' => $a['pfsync_iface'] ?? '',
                        'proto' => 'pfsync',
                        'action' => 'pass',
                        'description' => 'Allow pfsync for HA'
                    ],
                    'note' => 'Allow pfsync protocol on sync interface'
                ];
                $ops[] = [
                    'type' => 'rule_anchor_note',
                    'path' => '',
                    'value' => [],
                    'note' => 'HA: CARP, pfsync, and XMLRPC sync configured.'
                ];
                $impacts = [
                    'Enabling CARP may briefly interrupt traffic upon apply.',
                    'State sync and config sync settings will be changed.'
                ];
                $risks = [
                    'Ensure unique VHIDs and matching CARP passwords.',
                    'Ensure pfsync network is isolated.'
                ];
                $explanation = 'Configures High Availability (CARP, pfsync, XMLRPC sync) for two-node cluster.';
                break;
            case 'multiwan':
                $wan_ifaces = array_map('trim', explode(',', $a['wan_ifaces'] ?? 'wan,wan2'));
                $mode = strtolower(trim($a['mode'] ?? 'failover'));
                $weights = (!empty($a['weights'])) ? array_map('trim', explode(',', $a['weights'])) : [];
                $monitor_ips = (!empty($a['monitor_ips'])) ? array_map('trim', explode(',', $a['monitor_ips'])) : [];
                $trigger_level = $a['trigger_level'] ?? 'packet-loss';

                $ops[] = [
                    'type' => 'gateway_group_add',
                    'path' => 'gateways/gateway_group[+]',
                    'value' => [
                        'interfaces' => $wan_ifaces,
                        'mode' => $mode,
                        'weights' => $weights,
                        'monitor_ips' => $monitor_ips,
                        'trigger_level' => $trigger_level
                    ],
                    'note' => 'Add gateway group for Multi-WAN'
                ];
                $ops[] = [
                    'type' => 'firewall_rule_add',
                    'path' => 'filter/rule[+]',
                    'value' => [
                        'interface' => 'lan',
                        'action' => 'policy-route',
                        'gateway_group' => 'ai_group',
                        'description' => 'Default LAN policy-route to gateway group'
                    ],
                    'note' => 'Policy routing rule for LAN to gateway group'
                ];
                $ops[] = [
                    'type' => 'rule_anchor_note',
                    'path' => '',
                    'value' => [],
                    'note' => 'Multi-WAN (' . strtoupper($mode) . ') with group and policy routing.'
                ];
                $impacts = [
                    'Establishes policy routing; may temporarily disrupt flows on apply.'
                ];
                $risks = [
                    'Sticky connections and session persistence.',
                    'DNS egress consistency.'
                ];
                $explanation = 'Sets up Multi-WAN with gateway group and policy-based routing.';
                break;
            case 'vpn':
                $vpn_type = strtolower(trim($a['vpn_type'] ?? 'openvpn'));
                $impacts = [
                    'VPN setup may affect routing and firewall rules.',
                    'Auth misconfiguration can cause management lockout.'
                ];
                $risks = [
                    'Ensure authentication details are correct.',
                    'Test remote access before decommissioning old configs.'
                ];
                if ($vpn_type === 'openvpn') {
                    $ops[] = [
                        'type' => 'openvpn_server_add',
                        'path' => 'openvpn/server[+]',
                        'value' => [
                            'port' => $a['openvpn_port'] ?? 1194,
                            'proto' => $a['openvpn_proto'] ?? 'udp',
                            'auth' => $a['openvpn_auth'] ?? 'cert',
                            'tunnel_network' => $a['openvpn_tun'] ?? '',
                            'local_networks' => $a['openvpn_localnets'] ?? '',
                            'dns' => $a['openvpn_dns'] ?? ''
                        ],
                        'note' => 'Add OpenVPN server'
                    ];
                    $ops[] = [
                        'type' => 'firewall_rule_add',
                        'path' => 'filter/rule[+]',
                        'value' => [
                            'interface' => 'wan',
                            'proto' => $a['openvpn_proto'] ?? 'udp',
                            'port' => $a['openvpn_port'] ?? 1194,
                            'action' => 'pass',
                            'description' => 'Allow OpenVPN server'
                        ],
                        'note' => 'Allow OpenVPN port on WAN'
                    ];
                    $ops[] = [
                        'type' => 'interface_assign',
                        'path' => 'interfaces/opt[+]',
                        'value' => [
                            'interface' => 'ovpn_server'
                        ],
                        'note' => 'Assign OpenVPN interface'
                    ];
                    $ops[] = [
                        'type' => 'rule_anchor_note',
                        'path' => '',
                        'value' => [],
                        'note' => 'OpenVPN server and firewall rule configured.'
                    ];
                } else {
                    // IPsec
                    $ops[] = [
                        'type' => 'ipsec_phase1_add',
                        'path' => 'ipsec/phase1[+]',
                        'value' => [
                            'peer_ip' => $a['ipsec_peer_ip'] ?? '',
                            'auth' => $a['ipsec_auth'] ?? 'psk',
                            'phase1' => $a['ipsec_phase1'] ?? 'AES256/SHA256',
                            'lifetime' => $a['ipsec_p1_lifetime'] ?? 28800
                        ],
                        'note' => 'Add IPsec Phase1'
                    ];
                    $ops[] = [
                        'type' => 'ipsec_phase2_add',
                        'path' => 'ipsec/phase2[+]',
                        'value' => [
                            'local' => $a['ipsec_p2_local'] ?? '',
                            'remote' => $a['ipsec_p2_remote'] ?? '',
                            'lifetime' => $a['ipsec_p2_lifetime'] ?? 3600
                        ],
                        'note' => 'Add IPsec Phase2'
                    ];
                    $ops[] = [
                        'type' => 'firewall_rule_add',
                        'path' => 'filter/rule[+]',
                        'value' => [
                            'interface' => 'wan',
                            'proto' => 'esp',
                            'action' => 'pass',
                            'description' => 'Allow IPsec'
                        ],
                        'note' => 'Allow IPsec traffic on WAN'
                    ];
                    $ops[] = [
                        'type' => 'rule_anchor_note',
                        'path' => '',
                        'value' => [],
                        'note' => 'IPsec phases and firewall adjustment previewed.'
                    ];
                }
                $explanation = ($vpn_type === 'openvpn')
                    ? 'Configures an OpenVPN server with chosen authentication and firewall rules.'
                    : 'Configures IPsec tunnels (Phase1/Phase2) and firewall rules.';
                break;
            default:
                $explanation = 'Unknown wizard type.';
                break;
        }
        return [
            'operations' => $ops,
            'impacts' => $impacts,
            'risk_warnings' => $risks,
            'explanation' => $explanation
        ];
    }

    // Utility: get question order for type and branch
    protected static function getOrderedKeys($type, $answers, $branch)
    {
        if ($type !== 'vpn') {
            return array_keys(self::$wizardQuestions[$type]);
        }
        // VPN wizard: ask vpn_type first, then branch-specific
        $keys = ['vpn_type'];
        $branch = $branch ?? (isset($answers['vpn_type']) && strtolower(trim($answers['vpn_type'])) === 'ipsec' ? 'ipsec' : 'openvpn');
        foreach (array_keys(self::$wizardQuestions['vpn']) as $k) {
            if ($k === 'vpn_type') continue;
            if (strpos($k, $branch) === 0) $keys[] = $k;
        }
        return $keys;
    }

    // Utility: get current questions for state
    protected static function getQuestions($type, $state)
    {
        $collected = $state['__answers'] ?? [];
        $branch = $state['__branch'] ?? null;
        $order = self::getOrderedKeys($type, $collected, $branch);
        $step = $state['__step'] ?? 0;
        $remaining = array_slice($order, $step);
        $qs = [];
        foreach ($remaining as $key) {
            // Only include relevant branch questions for VPN
            if ($type === 'vpn' && $branch && strpos($key, $branch) !== 0 && $key !== 'vpn_type') continue;
            $qs[$key] = self::$wizardQuestions[$type][$key];
            break; // Only ask one at a time
        }
        return $qs;
    }
}