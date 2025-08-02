<?php
/*
 * diag_ai_attack_console.php
 * Minimal MITRE ATT&CK console for pfSense AI
 */
require_once("guiconfig.inc");
require_once("/etc/inc/attack.inc");

$blocklist_file = "/var/db/ai_blocklist.json";
$rows = file_exists($blocklist_file) ? json_decode(file_get_contents($blocklist_file), true) : [];
if (!is_array($rows)) $rows = [];
$tactics = [];
foreach ($rows as $r) {
    if (!empty($r['attack_tactic'])) $tactics[$r['attack_tactic']] = true;
}
$tactics = array_keys($tactics);
sort($tactics);

$selected_tactic = $_GET['tactic'] ?? '';
$filtered_rows = $selected_tactic ?
    array_filter($rows, fn($r) => $r['attack_tactic'] === $selected_tactic) : $rows;

function killchain_viz($tactic) {
    $chain = [
        'Reconnaissance','Resource Development','Initial Access','Execution','Persistence','Privilege Escalation','Defense Evasion',
        'Credential Access','Discovery','Lateral Movement','Collection','Command and Control','Exfiltration','Impact'
    ];
    $idx = array_search($tactic, $chain);
    $out = '<div class="progress" style="height:18px;background:#222;">';
    $n = count($chain);
    foreach ($chain as $i => $name) {
        $color = ($i == $idx) ? 'background:#00ff00;' : 'background:#111;';
        $width = 100/$n;
        $out .= '<div class="progress-bar" style="'.$color.'width:'.$width.'%;">'.($i == $idx ? $name : '&nbsp;').'</div>';
    }
    $out .= '</div>';
    return $out;
}

include("head.inc");
?>
<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title">ATT&CK Console</h2></div>
  <div class="panel-body">
    <form method="get" class="form-inline mb-2">
      <label for="tactic">Filter by Tactic: </label>
      <select name="tactic" id="tactic" onchange="this.form.submit()" class="form-control">
        <option value="">All</option>
        <?php foreach($tactics as $t): ?>
            <option value="<?=htmlspecialchars($t)?>" <?=($selected_tactic===$t)?'selected':''?>><?=htmlspecialchars($t)?></option>
        <?php endforeach; ?>
      </select>
    </form>
    <table class="table table-striped">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>IP</th>
          <th>Reason</th>
          <th>ATT&CK ID</th>
          <th>Tactic</th>
          <th>Technique</th>
          <th>Playbook</th>
        </tr>
      </thead>
      <tbody>
        <?php foreach($filtered_rows as $row): ?>
          <tr>
            <td><?=htmlspecialchars($row['ts'] ?? '')?></td>
            <td><?=htmlspecialchars($row['ip'] ?? '')?></td>
            <td><?=htmlspecialchars($row['reason'] ?? '')?></td>
            <td><?=htmlspecialchars($row['attack_id'] ?? '')?></td>
            <td><?=htmlspecialchars($row['attack_tactic'] ?? '')?></td>
            <td><?=htmlspecialchars($row['attack_technique'] ?? '')?></td>
            <td>
              <?php if (!empty($row['attack_id'])): ?>
                <a class="btn btn-xs btn-info" target="_blank" href="https://attack.mitre.org/techniques/<?=htmlspecialchars($row['attack_id'])?>">Playbook</a>
              <?php endif; ?>
            </td>
          </tr>
          <?php if (!empty($row['attack_tactic'])): ?>
            <tr>
              <td colspan="7"><?=killchain_viz($row['attack_tactic'])?></td>
            </tr>
          <?php endif; ?>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
</div>
<?php include("foot.inc"); ?>