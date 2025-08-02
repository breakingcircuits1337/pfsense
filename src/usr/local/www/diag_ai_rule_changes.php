<?php
/*
 * diag_ai_rule_changes.php
 * View AI-made IDS rule changes
 */
require_once("guiconfig.inc");
require_once("/etc/inc/ids.inc");

$logfile = "/var/db/ai_rule_changes.log";
$rows = [];
if (file_exists($logfile)) {
    $lines = file($logfile);
    foreach ($lines as $l) {
        $row = @json_decode($l, true);
        if (is_array($row)) $rows[] = $row;
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['clear'])) {
    @unlink($logfile);
    $rows = [];
    $savemsg = "Log cleared.";
}
include("head.inc");
?>
<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title">AI-driven IDS Rule Changes</h2></div>
  <div class="panel-body">
    <?php if (!empty($savemsg)): ?>
      <div class="alert alert-success"><?=$savemsg?></div>
    <?php endif; ?>
    <form method="post">
      <button class="btn btn-danger" name="clear" value="1" onclick="return confirm('Clear all AI rule change logs?')">Clear Log</button>
    </form>
    <table class="table table-striped">
      <thead><tr>
        <th>Timestamp</th>
        <th>Engine</th>
        <th>Action</th>
        <th>SID</th>
        <th>Info</th>
      </tr></thead>
      <tbody>
      <?php foreach ($rows as $row): ?>
        <tr>
          <td><?=htmlspecialchars($row['ts'] ?? '')?></td>
          <td><?=htmlspecialchars($row['engine'] ?? '')?></td>
          <td><?=htmlspecialchars($row['action'] ?? '')?></td>
          <td><?=htmlspecialchars($row['sid'] ?? '')?></td>
          <td><?=htmlspecialchars($row['info'] ?? '')?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php include("foot.inc"); ?>