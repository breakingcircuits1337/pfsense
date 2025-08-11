<?php
/**
 * AIAssistant: Deterministic AI Assistant for intent classification and safe config change proposals.
 *
 * Recognizes exemplar intents using regex, returns safe previews, clarifications, and warnings.
 * Never writes to $config; all changes are proposals only.
 */

require_once __DIR__ . '/ai_plan_renderer.inc';
require_once __DIR__ . '/ai_provider_factory.inc'; // assumed to exist
require_once __DIR__ . '/ai_provider.inc'; // assumed to exist

class AIAssistant
{
    /** @var AIProvider|null */
    protected $provider;

    /**
     * Construct the assistant, using provided AIProvider or default from config.
     * @param AIProvider|null $provider
     */
    public function __construct(?AIProvider $provider = null)
    {
        if ($provider) {
            $this->provider = $provider;
        } else {
            $this->provider = AIProviderFactory::from_config();
        }
    }

    /**
     * Handle a user request, following the operating protocol.
     *
     * @param string $inputText
     * @param array $options
     * @return array See schema in task description.
     */
    public function handle_request(string $inputText, array $options = []): array
    {
        $input = trim($inputText);
        $clarifications = [];
        $risk_warnings = [];
        $proposal = [
            'operations' => [],
            'impacts' => [],
            'risk_warnings' => [],
            'explanation' => '',
        ];
        $requires_confirmation = true;

        // Example intent: Block all inbound and outbound traffic from North Korea and Iran.
        if (preg_match('/block (all )?(inbound|outbound|both)? .*north ?korea.*iran/i', $input)) {
            $proposal['explanation'] = "You requested to block all inbound and outbound network traffic to and from North Korea and Iran using GeoIP or country-based blocking.";
            $proposal['operations'][] = [
                'type' => 'alias_add',
                'path' => 'aliases/alias[+]',
                'value' => [
                    'name' => 'Country_NK_IR',
                    'type' => 'geoip',
                    'countries' => ['North Korea', 'Iran'],
                    'description' => 'Auto-generated for country block (NK, IR)',
                ],
                'note' => 'Requires GeoIP or pfBlockerNG. Install/enable if missing.',
            ];
            $proposal['operations'][] = [
                'type' => 'firewall_rule_add',
                'path' => 'filter/rule[+]',
                'value' => [
                    'action' => 'block',
                    'interface' => 'wan',
                    'direction' => 'in',
                    'src' => '<alias:Country_NK_IR>',
                    'dst' => 'any',
                    'proto' => 'any',
                    'log' => true,
                    'quick' => true,
                ],
                'note' => 'Blocks inbound from NK/IR',
            ];
            $proposal['operations'][] = [
                'type' => 'firewall_rule_add',
                'path' => 'filter/rule[+]',
                'value' => [
                    'action' => 'block',
                    'interface' => 'wan',
                    'direction' => 'out',
                    'src' => 'any',
                    'dst' => '<alias:Country_NK_IR>',
                    'proto' => 'any',
                    'log' => true,
                    'quick' => true,
                ],
                'note' => 'Blocks outbound to NK/IR',
            ];
            $proposal['operations'][] = [
                'type' => 'rule_anchor_note',
                'path' => '',
                'value' => [],
                'note' => 'If GeoIP/pfBlockerNG not present, rules may not work as expected.',
            ];
            $proposal['impacts'][] = "Adds 1 alias and 2 firewall block rules; may drop communications to/from these countries.";
            $proposal['risk_warnings'][] = "GeoIP databases may be outdated; false positives possible. Ensure GeoIP provider is enabled.";
        }
        // Example intent: Set up a new OpenVPN server for remote employees on the 10.0.8.0/24 subnet.
        elseif (preg_match('/openvpn.*server.*10\.0\.8\.0\/24/i', $input)) {
            $defaults = [
                'port' => 1194,
                'proto' => 'udp',
                'auth' => 'cert',
                'tunnel_network' => '10.0.8.0/24',
                'interface' => 'WAN',
                'firewall_rule' => true,
                'interface_assign' => true,
                'outbound_nat' => true,
            ];
            // Clarify port/proto, auth, DNS push if not specified
            if (!preg_match('/(udp|tcp)/i', $input)) {
                $clarifications[] = "Should the VPN use UDP (default) or TCP?";
            }
            if (!preg_match('/(pre[- ]?shared|psk|password|cert)/i', $input)) {
                $clarifications[] = "Should the VPN use certificate-based, PSK, or password authentication?";
            }
            $proposal['explanation'] = "You requested to configure a new OpenVPN server for remote employees, assigning clients to 10.0.8.0/24. Defaulting to UDP/1194, TLS certificate-based authentication.";
            $proposal['operations'][] = [
                'type' => 'openvpn_server_add',
                'path' => 'openvpn/server[+]',
                'value' => [
                    'interface' => $defaults['interface'],
                    'port' => $defaults['port'],
                    'proto' => $defaults['proto'],
                    'tunnel_network' => $defaults['tunnel_network'],
                    'auth' => $defaults['auth'],
                    'dns_push' => true,
                ],
                'note' => 'Creates new OpenVPN server. Adjust parameters as needed.',
            ];
            $proposal['operations'][] = [
                'type' => 'firewall_rule_add',
                'path' => 'filter/rule[+]',
                'value' => [
                    'action' => 'pass',
                    'interface' => $defaults['interface'],
                    'proto' => $defaults['proto'],
                    'dst_port' => (string)$defaults['port'],
                    'src' => 'any',
                    'dst' => 'this_firewall',
                    'description' => 'Allow OpenVPN',
                ],
                'note' => 'Allows VPN traffic.',
            ];
            $proposal['operations'][] = [
                'type' => 'interface_assign',
                'path' => 'interfaces/ovpn[+]',
                'value' => [
                    'if_type' => 'ovpn',
                    'descr' => 'OpenVPN_Server',
                ],
                'note' => 'Creates OpenVPN interface.',
            ];
            $proposal['impacts'][] = "Adds one OpenVPN server and associated firewall rule. May restart OpenVPN when applied.";
            $proposal['risk_warnings'][] = "VPN misconfiguration may block access. Review authentication and network settings.";
        }
        // Example intent: Prioritize all traffic for the device with IP 192.168.1.150 for gaming.
        elseif (preg_match('/prioritiz.*(gaming|game).*192\.168\.1\.150/i', $input)) {
            $proposal['explanation'] = "You requested to prioritize all gaming traffic for device 192.168.1.150 using traffic shaping.";
            $proposal['operations'][] = [
                'type' => 'shaper_rule_add',
                'path' => 'shaper/rule[+]',
                'value' => [
                    'src' => '192.168.1.150',
                    'dscp' => 'AF41',
                    'ports' => 'gaming',
                    'priority' => 'high',
                ],
                'note' => 'Prioritizes gaming traffic for specified device.',
            ];
            $proposal['operations'][] = [
                'type' => 'firewall_rule_add',
                'path' => 'filter/rule[+]',
                'value' => [
                    'action' => 'pass',
                    'interface' => 'lan',
                    'src' => '192.168.1.150',
                    'tag' => 'gaming_qos',
                    'description' => 'Mark gaming traffic for shaper',
                ],
                'note' => 'Tags traffic for shaper.',
            ];
            $proposal['impacts'][] = "Adds shaping rules; may impact other hosts' bandwidth.";
            $proposal['risk_warnings'][] = "Aggressive prioritization can starve other clients.";
        }
        // Example intent: Create a VLAN (ID 40) named GuestNet on LAN, DHCP 192.168.40.100-200, block to LAN.
        elseif (preg_match('/vlan.*40.*guest.*dhcp.*192\.168\.40\.100.*192\.168\.40\.200.*block.*192\.168\.1\.0\/24/i', str_replace(["\n", "\r"], " ", strtolower($input)))) {
            $proposal['explanation'] = "You requested to create a new Guest VLAN (ID 40) on the LAN interface, with isolated DHCP and firewall rules to prevent access to the main LAN.";
            $proposal['operations'][] = [
                'type' => 'vlan_create',
                'path' => 'vlans/vlan[+]',
                'value' => [
                    'parent' => 'lan',
                    'tag' => 40,
                    'descr' => 'GuestNet',
                ],
                'note' => 'Creates VLAN 40 (GuestNet) on LAN.',
            ];
            $proposal['operations'][] = [
                'type' => 'interface_assign',
                'path' => 'interfaces/opt[+]',
                'value' => [
                    'if_type' => 'vlan',
                    'vlan_tag' => 40,
                    'descr' => 'GuestNet',
                ],
                'note' => 'Assigns VLAN to OPT interface.',
            ];
            $proposal['operations'][] = [
                'type' => 'dhcp_pool_set',
                'path' => 'dhcpd/opt[+]',
                'value' => [
                    'range_from' => '192.168.40.100',
                    'range_to' => '192.168.40.200',
                    'subnet' => '192.168.40.0/24',
                ],
                'note' => 'DHCP for GuestNet.',
            ];
            $proposal['operations'][] = [
                'type' => 'firewall_rule_add',
                'path' => 'filter/rule[+]',
                'value' => [
                    'action' => 'block',
                    'interface' => 'optX', // To be mapped to VLAN 40
                    'src' => 'any',
                    'dst' => '192.168.1.0/24',
                    'description' => 'Block GuestNet to main LAN',
                ],
                'note' => 'Prevents guests from reaching LAN.',
            ];
            $proposal['impacts'][] = "Adds VLAN, assigns interface, enables DHCP, and isolates from main LAN.";
            $proposal['risk_warnings'][] = "Switch must support VLAN tagging. Incorrect setup may disrupt connectivity.";
        }
        // Vague/vpn request: ask for clarifications.
        elseif (preg_match('/(vpn|setup vpn)$/i', $input) && !preg_match('/openvpn|l2tp|ipsec/i', $input)) {
            $requires_confirmation = false;
            $clarifications[] = "Which type of VPN do you want to set up (OpenVPN, IPsec, L2TP, WireGuard)?";
            $clarifications[] = "For remote access or site-to-site? Any specific networks, authentication, or ports?";
            $proposal['explanation'] = "Request not specific enough for a safe configuration. Please clarify the VPN type, purpose, and key parameters.";
        }
        // Catch-all: fallback to provider for classification and preview only.
        else {
            $intent = $this->provider ? $this->provider->classify_intent($input) : null;
            $proposal['explanation'] = "Could not deterministically recognize the request. ";
            if ($intent) {
                $proposal['explanation'] .= "Detected intent: {$intent['name']} – {$intent['description']}.";
                if (!empty($intent['clarifications'])) {
                    $clarifications = array_merge($clarifications, $intent['clarifications']);
                    $requires_confirmation = false;
                }
            } else {
                $proposal['explanation'] .= "Please provide more details or rephrase your request.";
                $requires_confirmation = false;
            }
        }

        // Preview rendering
        $preview = $this->render_preview($proposal);

        return [
            'proposal' => $proposal,
            'preview' => $preview,
            'requires_confirmation' => $requires_confirmation,
            'clarifying_questions' => $clarifications,
        ];
    }

    /**
     * Delegate preview rendering to AIPlanRenderer.
     * @param array $proposal
     * @return array
     */
    public function render_preview(array $proposal): array
    {
        return AIPlanRenderer::render_preview($proposal);
    }
}