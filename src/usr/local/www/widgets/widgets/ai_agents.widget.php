<?php
/*
 * ai_agents.widget.php
 * Dashboard Widget for AI Security Ecosystem
 * Displays status of autonomous agents and live threat feed.
 */

require_once("guiconfig.inc");
require_once("/etc/inc/util.inc");

// Function to check if a specific agent daemon is running
function is_agent_running($name) {
    $pidfile = "/var/run/ai_agent_{$name}.pid";
    // Honeypot naming exception
    if ($name === 'honeypot') $pidfile = "/var/run/ai_honeypot.pid";

    if (file_exists($pidfile)) {
        $pid = trim(file_get_contents($pidfile));
        if (is_numeric($pid) && posix_kill($pid, 0)) {
            return true;
        }
    }
    return false;
}

// Get latest events
function get_ai_events($limit = 5) {
    $logfile = '/var/db/ai_events.log';
    if (!file_exists($logfile)) return [];

    // Read last N lines safely
    $lines = [];
    exec("tail -n " . intval($limit) . " " . escapeshellarg($logfile), $lines);
    $events = [];
    foreach (array_reverse($lines) as $line) {
        $data = json_decode($line, true);
        if ($data) {
            // Add relative time
            $data['rel_time'] = time_ago($data['timestamp'] ?? time());
            $events[] = $data;
        }
    }
    return $events;
}

function time_ago($ts) {
    $diff = time() - $ts;
    if ($diff < 60) return $diff . "s ago";
    if ($diff < 3600) return floor($diff/60) . "m ago";
    return floor($diff/3600) . "h ago";
}

$agents = [
    'steward' => 'The Steward',
    'gatekeeper' => 'The Gatekeeper',
    'inquisitor' => 'The Inquisitor',
    'void' => 'The Void',
    'warden' => 'The Warden',
    'honeypot' => 'Honeypot'
];

$events = get_ai_events(8);
?>

<div class="panel panel-default">
    <div class="panel-heading"><h2 class="panel-title">AI Security Ecosystem</h2></div>
    <div class="panel-body">

        <!-- Agent Status Grid -->
        <div class="row" style="margin-bottom: 15px;">
            <?php foreach ($agents as $id => $label): ?>
                <?php $status = is_agent_running($id); ?>
                <div class="col-xs-4 col-sm-4 col-md-4" style="text-align: center; margin-bottom: 10px;">
                    <i class="fa fa-circle" style="color: <?= $status ? '#5cb85c' : '#d9534f' ?>;"></i>
                    <br>
                    <small><strong><?=htmlspecialchars($label)?></strong></small>
                </div>
            <?php endforeach; ?>
        </div>

        <hr>

        <!-- Live Feed -->
        <h5><strong>Live Intel Feed</strong></h5>
        <table class="table table-condensed table-hover table-striped">
            <tbody>
                <?php if (empty($events)): ?>
                    <tr><td colspan="3" class="text-center"><i>No recent events</i></td></tr>
                <?php else: ?>
                    <?php foreach ($events as $ev): ?>
                        <tr>
                            <td style="width: 20%;">
                                <?php if (($ev['type'] ?? '') === 'block'): ?>
                                    <span class="label label-danger">BLOCK</span>
                                <?php elseif (($ev['type'] ?? '') === 'suspicious'): ?>
                                    <span class="label label-warning">WARN</span>
                                <?php else: ?>
                                    <span class="label label-info">INFO</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <strong><?=htmlspecialchars($ev['ip'] ?? 'N/A')?></strong><br>
                                <small><?=htmlspecialchars($ev['reason'] ?? '')?></small>
                            </td>
                            <td style="width: 20%; text-align: right;">
                                <small><?=htmlspecialchars($ev['rel_time'])?></small>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
        </table>

        <div class="text-right">
             <a href="/diag_ai_threats.php" class="btn btn-xs btn-default">View Full Logs</a>
             <a href="/services_ai_settings.php" class="btn btn-xs btn-default">Settings</a>
        </div>
    </div>
</div>

<script>
// Simple auto-refresh for the widget content if needed,
// but pfSense dashboard usually handles refreshing via AJAX if registered correctly.
</script>
