<?php
/*
 * diag_ai_threats.php
 * pfSense AI Threat Monitor Blocklist UI
 */
require_once("guiconfig.inc");
require_once("/etc/inc/util.inc");
require_once("/etc/inc/ai.inc");

$blocklist_file = "/var/db/ai_blocklist.json";
$monitor_enable = $config['system']['ai']['monitor']['enable'] ?? false;
$rows = [];
if (file_exists($blocklist_file)) {
    $contents = file_get_contents($blocklist_file);
    $rows = json_decode($contents, true);
    if (!is_array($rows)) $rows = [];
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['unblock']) && is_array($_POST['unblock'])) {
        foreach ($_POST['unblock'] as $ip) {
            mwexec("/sbin/pfctl -t ai_blocklist -T delete " . escapeshellarg($ip));
            // Remove from file
            $rows = array_filter($rows, function($row) use ($ip) { return $row['ip'] !== $ip; });
        }
        file_put_contents($blocklist_file, json_encode(array_values($rows)));
        $savemsg = "Selected IP(s) unblocked.";
    } elseif (isset($_POST['clear_all'])) {
        mwexec("/sbin/pfctl -t ai_blocklist -T flush");
        file_put_contents($blocklist_file, json_encode([]));
        $rows = [];
        $savemsg = "Blocklist cleared.";
    } elseif (isset($_POST['monitor_toggle'])) {
        $config['system']['ai']['monitor']['enable'] = !empty($_POST['monitor_on']) ? true : false;
        write_config("AI Threat Monitor " . ($_POST['monitor_on'] ? "enabled" : "disabled"));
        if ($config['system']['ai']['monitor']['enable']) {
            service_control_restart("ai_threat_monitor");
        } else {
            mwexec("/etc/rc.d/ai_threat_monitor stop");
        }
        $monitor_enable = $config['system']['ai']['monitor']['enable'];
        $savemsg = "Threat Monitor " . ($monitor_enable ? "enabled" : "disabled") . ".";
    }
}

include("head.inc");
?>

<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title">AI Threat Monitor</h2></div>
  <div class="panel-body">
    <?php if (!empty($savemsg)): ?>
      <div class="alert alert-success"><?=$savemsg?></div>
    <?php endif; ?>
    <form method="post" class="mb-3">
      <button class="btn btn-<?= $monitor_enable ? 'danger' : 'success' ?>" name="monitor_toggle" value="1">
        <?= $monitor_enable ? 'Disable' : 'Enable' ?> Threat Monitor
      </button>
      <input type="hidden" name="monitor_on" value="<?= $monitor_enable ? '' : '1' ?>">
      <button class="btn btn-warning" name="clear_all" value="1" type="submit" onclick="return confirm('Clear all blocked IPs?');">Clear All</button>
    </form>
    <form method="post" id="blocklistform">
      <table class="table table-striped">
        <thead>
          <tr>
            <th><input type="checkbox" id="selectall"></th>
            <th>IP Address</th>
            <th>First Seen</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($rows as $row): ?>
            <tr>
              <td><input type="checkbox" name="unblock[]" value="<?=htmlspecialchars($row['ip'])?>"></td>
              <td><?=htmlspecialchars($row['ip'])?></td>
              <td><?=htmlspecialchars($row['ts'])?></td>
              <td><?=htmlspecialchars($row['reason'])?></td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
      <button class="btn btn-danger" type="submit">Unblock Selected</button>
    </form>
  </div>
</div>
<script>
// Select all
document.getElementById('selectall').onclick = function() {
  var boxes = document.querySelectorAll('input[name="unblock[]"]');
  for (var i=0; i<boxes.length; i++) { boxes[i].checked = this.checked; }
};

// SSE event stream
if (!!window.EventSource) {
  const evtSrc = new EventSource('/api/ai_events.php');
  evtSrc.addEventListener('block', function(e) {
    var data = JSON.parse(e.data);
    // Add new row if not exists
    if (!document.querySelector('input[value="'+data.ip+'"]')) {
      var tbody = document.querySelector('table tbody');
      var row = document.createElement('tr');
      row.innerHTML = '<td><input type="checkbox" name="unblock[]" value="'+data.ip+'"></td>' +
                      '<td>'+data.ip+'</td>' +
                      '<td>'+data.ts+'</td>' +
                      '<td>'+data.reason+'</td>';
      tbody.appendChild(row);
    }
    alert("AI blocked IP " + data.ip + ": " + data.reason);
  });
  evtSrc.addEventListener('unblock', function(e) {
    var data = JSON.parse(e.data);
    // Remove row
    var box = document.querySelector('input[value="'+data.ip+'"]');
    if (box) {
      var row = box.closest('tr');
      row.parentNode.removeChild(row);
    }
    alert("AI unblocked IP " + data.ip);
  });
}
</script>
<?php include("foot.inc"); ?>