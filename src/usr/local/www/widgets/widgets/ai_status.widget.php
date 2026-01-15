<?php
/*
 * ai_status.widget.php
 *
 * Dashboard Widget for AI Intelligent Defender
 * Displays Service Status, Queue Depth, and Recent Blocks.
 */

require_once("guiconfig.inc");
require_once("/etc/inc/ai_queue.inc");
require_once("/etc/inc/util.inc");

// AJAX Handler for updates
if (isset($_REQUEST['get_ai_stats'])) {
    $stats = [
        'collector' => is_pid_running('/var/run/ai_log_collector.pid'),
        'monitor' => is_pid_running('/var/run/ai_threat_monitor.pid'),
        'queue' => 0,
        'blocks' => []
    ];

    try {
        $q = new AIQueue();
        $stats['queue'] = $q->count();
    } catch (Exception $e) {
        $stats['queue'] = 'Err';
    }

    $blocklist_file = "/var/db/ai_blocklist.json";
    if (file_exists($blocklist_file)) {
        $list = json_decode(file_get_contents($blocklist_file), true);
        if (is_array($list)) {
            // Get last 5
            $stats['blocks'] = array_slice(array_reverse($list, true), 0, 5);
        }
    }

    echo json_encode($stats);
    exit;
}

function is_pid_running($pidfile)
{
    if (file_exists($pidfile)) {
        $pid = trim(file_get_contents($pidfile));
        if (is_numeric($pid) && posix_kill($pid, 0)) {
            return true;
        }
    }
    return false;
}
?>

<div class="table-responsive">
    <table class="table table-hover table-condensed">
        <thead>
            <tr>
                <th>Component</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td>Log Collector Service</td>
                <td id="ai_collector_status"><i class="fa fa-spinner fa-spin"></i></td>
            </tr>
            <tr>
                <td>Threat Analyzer Service</td>
                <td id="ai_monitor_status"><i class="fa fa-spinner fa-spin"></i></td>
            </tr>
            <tr>
                <td>Analysis Queue Depth</td>
                <td id="ai_queue_depth"><i class="fa fa-spinner fa-spin"></i></td>
            </tr>
        </tbody>
    </table>
</div>

<div class="panel panel-default">
    <div class="panel-heading">
        <h4 class="panel-title">Recent AI Blocks</h4>
    </div>
    <div class="panel-body">
        <ul class="list-group" id="ai_recent_blocks">
            <li class="list-group-item">Loading...</li>
        </ul>
        <div class="text-center">
            <a href="/diag_ai_threats.php" class="btn btn-xs btn-primary">Manage Threat List</a>
        </div>
    </div>
</div>

<script type="text/javascript">
    function updateAIStats() {
        $.ajax({
            url: '/widgets/widgets/ai_status.widget.php?get_ai_stats=1',
            dataType: 'json',
            success: function (data) {
                // Statuses
                let up = '<span class="text-success"><i class="fa fa-check-circle"></i> Running</span>';
                let down = '<span class="text-danger"><i class="fa fa-times-circle"></i> Stopped</span>';

                $('#ai_collector_status').html(data.collector ? up : down);
                $('#ai_monitor_status').html(data.monitor ? up : down);
                $('#ai_queue_depth').text(data.queue + " items");

                // Blocks
                let list = $('#ai_recent_blocks');
                list.empty();
                if (Object.keys(data.blocks).length === 0) {
                    list.append('<li class="list-group-item">No recent blocks.</li>');
                } else {
                    $.each(data.blocks, function (ip, info) {
                        list.append('<li class="list-group-item"><strong>' + ip + '</strong><br><small>' + info.reason + '</small></li>');
                    });
                }
            }
        });
    }

    // Update every 5 seconds
    setInterval(updateAIStats, 5000);
    updateAIStats();
</script>