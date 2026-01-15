<?php
/*
 * puppet_master.widget.php
 * "Puppet Master" - Real-time Honeypot Monitoring & Interaction
 * Allows admins to view attacker sessions and deploy "Active Defense" measures.
 */

require_once("guiconfig.inc");

$session_dir = "/var/db/ai_sessions";
if (!is_dir($session_dir)) {
    // Attempt creation (on actual pfSense this runs as root)
    @mkdir($session_dir, 0755, true);
}

// AJAX Handler
if (isset($_REQUEST['pm_action'])) {
    $act = $_REQUEST['pm_action'];

    if ($act == 'list') {
        $sessions = [];
        $files = glob("$session_dir/*.json");
        if ($files) {
            foreach ($files as $f) {
                $data = json_decode(file_get_contents($f), true);
                if ($data) {
                    $data['id'] = basename($f, '.json');
                    $data['duration'] = time() - $data['start'];
                    $sessions[] = $data;
                }
            }
        }
        echo json_encode($sessions);
        exit;
    }

    if ($act == 'cmd' && isset($_REQUEST['sid']) && isset($_REQUEST['cmd'])) {
        $sid = basename($_REQUEST['sid']); // Sanitize
        $cmd = $_REQUEST['cmd'];
        $valid_cmds = ['pewpew', 'close', 'allow_login'];

        if (in_array($cmd, $valid_cmds)) {
            file_put_contents("$session_dir/$sid.cmd", $cmd);
            echo json_encode(['status' => 'ok', 'msg' => "Command $cmd sent to $sid"]);
        } else {
            echo json_encode(['status' => 'error', 'msg' => 'Invalid command']);
        }
        exit;
    }
}
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">Puppet Master Control</h2>
    </div>
    <div class="panel-body">
        <table class="table table-striped table-hover">
            <thead>
                <tr>
                    <th>Attacker IP</th>
                    <th>Persona</th>
                    <th>Duration</th>
                    <th>Peep Hole</th>
                    <th>Controls</th>
                </tr>
            </thead>
            <tbody id="pm_sessions">
                <tr>
                    <td colspan="5">Scanning active traps...</td>
                </tr>
            </tbody>
        </table>
    </div>
</div>

<!-- Terminal Modal -->
<div id="termModal" class="modal fade" role="dialog">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <button type="button" class="close" data-dismiss="modal">&times;</button>
                <h4 class="modal-title">Terminal Peep-Hole</h4>
            </div>
            <div class="modal-body">
                <pre id="termOutput" style="background:black; color:#0f0; height:400px; overflow:auto;"></pre>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn btn-danger" onclick="sendCmd('pewpew')">☢️ PEWPEW (Nuclear
                    DoS)</button>
                <button type="button" class="btn btn-warning" onclick="sendCmd('close')">Terminate</button>
                <button type="button" class="btn btn-default" data-dismiss="modal">Close</button>
            </div>
        </div>
    </div>
</div>

<script>
    var activeSid = null;

    function loadSessions() {
        $.ajax({
            url: '/widgets/widgets/puppet_master.widget.php',
            data: { pm_action: 'list' },
            dataType: 'json',
            success: function (data) {
                var tbody = $('#pm_sessions');
                tbody.empty();
                if (data.length === 0) {
                    tbody.append('<tr><td colspan="5">No active honeypot sessions. The traps are empty.</td></tr>');
                } else {
                    $.each(data, function (i, s) {
                        var btn = '<button class="btn btn-xs btn-info" onclick="openTerm(\'' + s.id + '\')">View</button>';
                        var row = '<tr>' +
                            '<td>' + s.ip + ':' + s.port + '</td>' +
                            '<td>' + s.persona + '</td>' +
                            '<td>' + s.duration + 's</td>' +
                            '<td>' + (s.buffer ? s.buffer.substring(s.buffer.length - 50) : '') + '...</td>' +
                            '<td>' + btn + '</td>' +
                            '</tr>';
                        tbody.append(row);

                        // Update modal if open
                        if (activeSid === s.id && $('#termModal').hasClass('in')) {
                            $('#termOutput').text(s.buffer);
                            var elem = document.getElementById('termOutput');
                            elem.scrollTop = elem.scrollHeight;
                        }
                    });
                }
            }
        });
    }

    function openTerm(sid) {
        activeSid = sid;
        $('#termOutput').text("Connecting to feed...");
        $('#termModal').modal('show');
    }

    function sendCmd(cmd) {
        if (!activeSid) return;
        if (cmd === 'pewpew') {
            if (!confirm("WARNING: This will flood the attacker's connection with garbage data to saturate their local link (Defensive Slow-Mirror). Proceed?")) return;
        }
        $.ajax({
            url: '/widgets/widgets/puppet_master.widget.php',
            data: { pm_action: 'cmd', sid: activeSid, cmd: cmd },
            dataType: 'json',
            success: function (res) {
                alert(res.msg);
                if (cmd === 'close' || cmd === 'pewpew') {
                    $('#termModal').modal('hide');
                }
            }
        });
    }

    // Poll every 2 seconds
    setInterval(loadSessions, 2000);
    loadSessions();
</script>