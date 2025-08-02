<?php
/*
 * firewall_ai_policy.php
 * Per-Interface & Per-Rule AI Policy Tuning
 * Copyright (c) 2024 The pfSense Contributors
 * All rights reserved.
 */

require_once("guiconfig.inc");
require_once("/etc/inc/interfaces.inc");
require_once("/etc/inc/filter.inc");
require_once("/etc/inc/ai.inc");

$mon_cfg = &$config['system']['ai']['monitor'];
if (!is_array($mon_cfg['interfaces'])) $mon_cfg['interfaces'] = [];
if (!is_array($mon_cfg['rules'])) $mon_cfg['rules'] = [];

// Handle POST (save)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['save'])) {
    // Interfaces
    foreach ($_POST['ifname'] as $idx => $ifname) {
        if ($ifname === '') continue;
        $en = isset($_POST['if_enable'][$ifname]);
        $thresh = trim($_POST['if_threshold'][$ifname]);
        $ttl = trim($_POST['if_ttl'][$ifname]);
        $entry = [];
        if ($en) $entry['enable'] = true;
        if ($thresh !== '') $entry['threshold'] = $thresh;
        if ($ttl !== '') $entry['ttl'] = $ttl;
        if (!empty($entry)) $mon_cfg['interfaces'][$ifname] = $entry;
        else unset($mon_cfg['interfaces'][$ifname]);
    }
    // Rules
    foreach ($_POST['rule_num'] as $idx => $rulenum) {
        if ($rulenum === '') continue;
        $en = isset($_POST['rule_enable'][$rulenum]);
        $thresh = trim($_POST['rule_threshold'][$rulenum]);
        $ttl = trim($_POST['rule_ttl'][$rulenum]);
        $entry = [];
        if ($en) $entry['enable'] = true;
        if ($thresh !== '') $entry['threshold'] = $thresh;
        if ($ttl !== '') $entry['ttl'] = $ttl;
        if (!empty($entry)) $mon_cfg['rules'][$rulenum] = $entry;
        else unset($mon_cfg['rules'][$rulenum]);
    }
    write_config(gettext("AI policy updated"));
    $savemsg = gettext("AI policy updated.");
}

// Gather interfaces
$iflist = get_configured_interface_with_descr(false, true);
// Gather rules
$rules = config_get_path('filter/rule', []);
include("head.inc");
?>

<div class="panel panel-default">
  <div class="panel-heading"><h2 class="panel-title"><?=gettext("AI Threat Policy – Interface Overrides")?></h2></div>
  <div class="panel-body">
    <?php if (!empty($savemsg)): ?>
      <div class="alert alert-success"><?=$savemsg?></div>
    <?php endif; ?>
    <form method="post" id="aipolicyform">
    <div class="alert alert-info">
      <?=gettext("Rule overrides take precedence over interface overrides, which take precedence over global defaults. Disabling at interface disables all rules unless a rule override re-enables. Leaving fields blank means 'use global default'.")?>
    </div>
    <table class="table table-striped">
      <thead>
        <tr>
          <th><?=gettext("Enable")?></th>
          <th><?=gettext("Interface")?></th>
          <th><?=gettext("Threshold")?></th>
          <th><?=gettext("TTL (hrs)")?></th>
        </tr>
      </thead>
      <tbody>
        <?php foreach ($iflist as $ifname => $ifdesc): 
          $p = $mon_cfg['interfaces'][$ifname] ?? [];
        ?>
        <tr>
          <td>
            <input type="checkbox" name="if_enable[<?=$ifname?>]" <?=!empty($p['enable'])?'checked':''?>>
            <input type="hidden" name="ifname[]" value="<?=$ifname?>">
          </td>
          <td><?=htmlspecialchars($ifdesc)?> (<?=htmlspecialchars($ifname)?>)</td>
          <td><input type="number" name="if_threshold[<?=$ifname?>]" min="0" max="1" step="0.05" class="form-control" value="<?=isset($p['threshold'])?$p['threshold']:''?>"></td>
          <td><input type="number" name="if_ttl[<?=$ifname?>]" min="1" step="1" class="form-control" value="<?=isset($p['ttl'])?$p['ttl']:''?>"></td>
        </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
    <hr>
    <div class="panel panel-default">
      <div class="panel-heading"><h2 class="panel-title"><?=gettext("AI Threat Policy – Rule Overrides")?></h2></div>
      <div class="panel-body">
        <table class="table table-striped">
          <thead>
            <tr>
              <th><?=gettext("Enable")?></th>
              <th><?=gettext("Rule #")?></th>
              <th><?=gettext("Description")?></th>
              <th><?=gettext("Interface")?></th>
              <th><?=gettext("Threshold")?></th>
              <th><?=gettext("TTL (hrs)")?></th>
            </tr>
          </thead>
          <tbody>
            <?php foreach ($rules as $r): 
              $tracker = $r['tracker'] ?? '';
              $p = $tracker ? ($mon_cfg['rules'][$tracker] ?? []) : [];
            ?>
            <tr>
              <td>
                <input type="checkbox" name="rule_enable[<?=$tracker?>]" <?=!empty($p['enable'])?'checked':''?>>
                <input type="hidden" name="rule_num[]" value="<?=$tracker?>">
              </td>
              <td><?=htmlspecialchars($tracker)?></td>
              <td><?=htmlspecialchars($r['descr'] ?? '')?></td>
              <td><?=htmlspecialchars($r['interface'] ?? '')?></td>
              <td><input type="number" name="rule_threshold[<?=$tracker?>]" min="0" max="1" step="0.05" class="form-control" value="<?=isset($p['threshold'])?$p['threshold']:''?>"></td>
              <td><input type="number" name="rule_ttl[<?=$tracker?>]" min="1" step="1" class="form-control" value="<?=isset($p['ttl'])?$p['ttl']:''?>"></td>
            </tr>
            <?php endforeach; ?>
          </tbody>
        </table>
      </div>
    </div>
    <button class="btn btn-primary" name="save" type="submit"><?=gettext("Save")?></button>
    </form>
  </div>
</div>

<?php include("foot.inc"); ?>