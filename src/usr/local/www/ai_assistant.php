<?php
/**
 * AI Assistant Web Panel (Preview & Apply)
 * - Assistant (natural language, LLM-backed)
 * - Analyze Rules (config audit)
 * - Wizards (guided config)
 * Always preview-only by default; guarded apply with explicit confirmation.
 */
require_once('guiconfig.inc');
if (!isAllowedPage(basename(__FILE__))) { header('HTTP/1.1 403 Forbidden'); echo gettext('Access denied.'); exit; }
require_once __DIR__ . '/../pfSense/include/vendor/autoload.php';
session_start();
if (empty($_SESSION['csrf'])) { $_SESSION['csrf'] = bin2hex(random_bytes(16)); }
$csrf = $_SESSION['csrf'];
$error = '';
$info = '';
$result = null;
$report = null;
$proposal = null;
$validate = null;
$tab = $_GET['tab'] ?? 'assistant';

// Simple tab router logic
function active_tab($name, $tab) { return $name === $tab ? 'style="font-weight:bold;text-decoration:underline;"' : ''; }
function esc($s) { return htmlspecialchars($s, ENT_QUOTES); }
function render_list($arr) { if (!$arr) return ''; $out = "<ul>"; foreach ($arr as $a) $out .= "<li>" . esc($a) . "</li>"; return $out . "</ul>"; }

// CSRF enforcement
function check_csrf() {
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf']) || $_POST['csrf'] !== $_SESSION['csrf']) {
      echo "<div style='color:red'>CSRF check failed. Please reload the page.</div>";
      exit;
    }
  }
}

// Main tab/page logic
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
  check_csrf();
  // ASSISTANT tab
  if ($_POST['action'] === 'preview_nl') {
    $tab = 'assistant';
    $provider_name = $_POST['provider'] ?? '';
    $nl_input = trim($_POST['nl_input'] ?? '');
    try {
      if (!$nl_input) throw new Exception("Please enter a request.");
      $provider = $provider_name ? AIProviderFactory::make($provider_name) : AIProviderFactory::from_config();
      $assistant = new AIAssistant($provider);
      $result = $assistant->handle_request($nl_input);
      $proposal = $result['proposal'] ?? null;
      if (!$proposal) throw new Exception("No proposal generated.");
    } catch (Exception $e) {
      $error = "Preview failed: " . $e->getMessage();
    }
  } elseif ($_POST['action'] === 'apply_nl') {
    $tab = 'assistant';
    try {
      $proposal = json_decode($_POST['proposal_json'] ?? '', true);
      if (!$proposal) throw new Exception("Invalid proposal. Please preview again.");
      $force = !empty($_POST['force']);
      $validate = AIApplyEngine::validateProposal($proposal);
      if (!$validate['valid'] && !$force) {
        throw new Exception("Validation failed: " . implode("; ", $validate['warnings'] ?? []) . " (Enable 'force apply' to override.)");
      }
      $res = AIApplyEngine::apply($proposal, ['confirm'=>true, 'force'=>$force]);
      $info = $res['applied']
        ? "Changes applied successfully. Subsystems reconfigured: " . implode(', ', $res['reconfigured'] ?? [])
        : "No changes applied: " . esc($res['message'] ?? '');
    } catch (Exception $e) {
      $error = "Apply failed: " . $e->getMessage();
    }
  }
  // ANALYZE RULES tab
  elseif ($_POST['action'] === 'analyze_rules') {
    $tab = 'analyze';
    try {
      $analysis = AIRuleAnalyzer::analyze();
      $report = AIRuleAnalyzer::renderReport($analysis);
      $proposal = $report['proposal'] ?? null;
    } catch (Exception $e) {
      $error = "Analyze failed: " . $e->getMessage();
    }
  } elseif ($_POST['action'] === 'apply_analysis') {
    $tab = 'analyze';
    try {
      $proposal = json_decode($_POST['proposal_json'] ?? '', true);
      if (!$proposal) throw new Exception("Invalid proposal.");
      $force = !empty($_POST['force']);
      $validate = AIApplyEngine::validateProposal($proposal);
      if (!$validate['valid'] && !$force) {
        throw new Exception("Validation failed: " . implode("; ", $validate['warnings'] ?? []) . " (Enable 'force apply' to override.)");
      }
      $res = AIApplyEngine::apply($proposal, ['confirm'=>true, 'force'=>$force]);
      $info = $res['applied']
        ? "Changes applied successfully. Subsystems reconfigured: " . implode(', ', $res['reconfigured'] ?? [])
        : "No changes applied: " . esc($res['message'] ?? '');
    } catch (Exception $e) {
      $error = "Apply failed: " . $e->getMessage();
    }
  }
  // WIZARDS tab
  elseif ($_POST['action'] === 'wizard_start') {
    $tab = 'wizards';
    $wiz_type = $_POST['wiz_type'] ?? '';
    if (!in_array($wiz_type, ['ha','multiwan','vpn'])) {
      $error = "Invalid wizard type.";
    } else {
      $state = AIWizards::start($wiz_type);
      $_SESSION['ai_wizard_type'] = $wiz_type;
      $_SESSION['ai_wizard_state'] = $state['state'];
      $_SESSION['ai_wizard_questions'] = $state['questions'];
    }
  }
  elseif ($_POST['action'] === 'wizard_next') {
    $tab = 'wizards';
    $wiz_type = $_SESSION['ai_wizard_type'] ?? '';
    $state = $_SESSION['ai_wizard_state'] ?? [];
    $answers = [];
    foreach ($_POST as $k => $v) {
      if (strpos($k, 'answer_') === 0) $answers[substr($k,7)] = $v;
    }
    $res = AIWizards::next($wiz_type, $state, $answers);
    $_SESSION['ai_wizard_state'] = $res['state'];
    $_SESSION['ai_wizard_questions'] = $res['questions'] ?? [];
    if (!empty($res['complete'])) {
      $proposal = AIWizards::buildProposal($wiz_type, $res['state']);
      $_SESSION['ai_wizard_proposal_json'] = json_encode($proposal);
    }
  }
  elseif ($_POST['action'] === 'wizard_apply') {
    $tab = 'wizards';
    try {
      $proposal = json_decode($_POST['proposal_json'] ?? '', true);
      if (!$proposal) throw new Exception("Invalid proposal.");
      $force = !empty($_POST['force']);
      $validate = AIApplyEngine::validateProposal($proposal);
      if (!$validate['valid'] && !$force) {
        throw new Exception("Validation failed: " . implode("; ", $validate['warnings'] ?? []) . " (Enable 'force apply' to override.)");
      }
      $res = AIApplyEngine::apply($proposal, ['confirm'=>true, 'force'=>$force]);
      $info = $res['applied']
        ? "Changes applied successfully. Subsystems reconfigured: " . implode(', ', $res['reconfigured'] ?? [])
        : "No changes applied: " . esc($res['message'] ?? '');
    } catch (Exception $e) {
      $error = "Apply failed: " . $e->getMessage();
    }
  }
}

// Utility: render apply confirmation modal
function render_apply_modal($proposal, $validate, $csrf, $action, $extra_fields = []) {
  $impacts = $proposal['impacts'] ?? [];
  $risk_warnings = $proposal['risk_warnings'] ?? [];
  $validate = $validate ?: AIApplyEngine::validateProposal($proposal);
  $affected = $validate['affected_subsystems'] ?? [];
  $force_required = !$validate['valid'] && !empty($validate['warnings']);
  $force_note = $force_required ? "<div style='color:red'><b>Warning:</b> Risk detected. You must check 'Force apply' to proceed.</div>" : "";
  $fields = "";
  foreach ($extra_fields as $k => $v) {
    $fields .= "<input type='hidden' name='" . esc($k) . "' value='" . esc($v) . "'>";
  }
  $proposal_json = esc(json_encode($proposal));
  echo <<<HTML
<div id="apply-modal" style="background:rgba(0,0,0,0.5);position:fixed;left:0;top:0;width:100%;height:100%;z-index:1000;display:flex;align-items:center;justify-content:center;">
  <form method="post" style="background:#fff;padding:2em;min-width:340px;max-width:480px;border-radius:8px;box-shadow:0 2px 8px #888;" onsubmit="document.getElementById('apply-btn').disabled=true;">
    <input type="hidden" name="csrf" value="{$csrf}">
    <input type="hidden" name="proposal_json" value="{$proposal_json}">
    <input type="hidden" name="action" value="{$action}">
    $fields
    <h3>Confirm Apply</h3>
    <b>Impacts:</b> {render_list($impacts)}
    <b>Affected subsystems:</b> {render_list($affected)}
    <b>Risk warnings:</b> {render_list($risk_warnings)}
    $force_note
    <label><input type="checkbox" id="confirm-check" onclick="document.getElementById('apply-btn').disabled=!this.checked;"> I understand the risks and want to proceed</label>
    <br>
    <label><input type="checkbox" name="force" value="1" id="force-check"> Force apply (override risk checks)</label>
    <br><br>
    <button type="submit" id="apply-btn" disabled>Apply Now</button>
    <button type="button" onclick="document.getElementById('apply-modal').remove();">Cancel</button>
  </form>
</div>
<script>document.getElementById('apply-btn').disabled = true;</script>
HTML;
}

<?php
// everything else remains inside <section class="page-content-main"> and will be wrapped by head.inc/footer.inc
?>
<section class="page-content-main">
  <style>
    .tabs { margin: 0 0 1em 0; padding: 0; background: #eef; }
    .tabs a { padding: 0.8em 1.5em; display: inline-block; color: #333; text-decoration: none; }
    .tabs a.active { background: #fff; border-bottom: 3px solid #3984e4; font-weight: bold; }
    .panel { background: #fff; border-radius: 6px; box-shadow: 0 2px 8px #e0e0e0; padding: 2em; margin-bottom: 2em; }
    .banner { background: #ffeedd; padding: .7em 1em; margin-bottom: 1em; border-radius: 4px; font-size: 1.06em; }
    h2 { color: #397; margin-top: 0; }
    pre { background: #f0f0f0; padding: 1em; border-radius: 3px; }
    .error { background: #fcc; padding: .5em 1em; border-radius: 4px; color: #800; margin-bottom: 1em; }
    .info { background: #efe; padding: .5em 1em; border-radius: 4px; color: #060; margin-bottom: 1em; }
    .impacts, .warnings { margin: .5em 0; }
    label { margin: .6em 0 .3em 0; display:block; font-weight:bold; }
    textarea { width: 100%; min-height: 70px; font-size: 1em; }
    select, input[type=text] { width: 100%; padding: .4em; margin-bottom: .5em; font-size:1em; }
    button { font-size:1em; padding:.5em 1.2em; margin:.4em 0; background:#3984e4; color:#fff; border:none;border-radius:3px; }
    button[disabled] { background:#bbb; }
    .tabcontent { display:none; }
    .tabcontent.active { display:block; }
    .about-panel { background: #eef; border-radius: 5px; margin-bottom: 1.5em; padding: 1.2em; }
    .about-toggle { float:right; font-size:.95em; cursor:pointer; color:#397; }
    .settings-link { float:right; font-size:.95em; margin-left:1.2em; }
  </style>
  <div class="tabs">
    <a href="?tab=assistant" <?=active_tab('assistant',$tab)?>>Assistant</a>
    <a href="?tab=analyze" <?=active_tab('analyze',$tab)?>>Analyze Rules</a>
    <a href="?tab=wizards" <?=active_tab('wizards',$tab)?>>Wizards</a>
  </div>
  <div class="about-panel">
    <span class="settings-link"><a href="/services_ai_settings.php" class="btn btn-xs btn-info">AI Settings</a></span>
    <span class="about-toggle" onclick="var x=document.getElementById('about-details');x.style.display=x.style.display==='none'?'block':'none';this.innerText=x.style.display==='none'?'[show more]':'[hide]';">[show more]</span>
    <b>About the AI Assistant:</b>
    <div id="about-details" style="display:none;">
      <ul>
        <li><b>Providers supported:</b> Ollama (local), Gemini, Mistral, Groq</li>
        <li><b>Keys and models:</b> Read from system/ai/* in config or environment variables. See <a href="/services_ai_settings.php">AI Settings</a> to configure.</li>
        <li><b>Safety protocol:</b>
          <ul>
            <li>Clarifies your intent and asks questions if ambiguous</li>
            <li>Explains and previews all proposed changes</li>
            <li>NEVER applies changes without explicit second confirmation</li>
            <li>Shows security warnings for risky operations (e.g., opening WAN, exposing admin ports)</li>
            <li>All changes are dry-run/preview by default; nothing is written until you confirm</li>
          </ul>
        </li>
      </ul>
    </div>
  </div>
  <div class="banner">
    <b>Security-first:</b> All changes are preview-only by default. <b>Second confirmation required to apply.</b> No changes are made until you explicitly confirm and apply.
  </div>
  <div style="max-width: 700px; margin: 0 auto;">
    <?php if ($error): ?><div class="error"><?=esc($error)?></div><?php endif; ?>
    <?php if ($info): ?><div class="info"><?=esc($info)?></div><?php endif; ?>
    <!-- Assistant Tab -->
    <div class="tabcontent<?= $tab==='assistant'?' active':'' ?>" id="tab-assistant">
      <div class="panel">
        <h2>AI Assistant</h2>
        <form method="post">
          <input type="hidden" name="csrf" value="<?=$csrf?>">
          <input type="hidden" name="action" value="preview_nl">
          <label for="provider">Provider:</label>
          <select name="provider" id="provider">
            <option value="ollama">Ollama (local)</option>
            <option value="gemini">Gemini</option>
            <option value="mistral">Mistral</option>
            <option value="groq">Groq</option>
          </select>
          <label for="nl_input">Request:</label>
          <textarea name="nl_input" id="nl_input"><?=isset($_POST['nl_input'])?esc($_POST['nl_input']):''?></textarea>
          <button type="submit">Preview</button>
        </form>
        <?php if ($result): ?>
          <div>
            <h3>Explanation</h3>
            <div><?=esc($result['proposal']['explanation'] ?? '')?></div>
            <h4>Preview</h4>
            <pre><?=esc($result['preview']['text'] ?? '')?></pre>
            <h4>Diff</h4>
            <pre><?=esc($result['preview']['diff'] ?? '')?></pre>
            <?php if (!empty($result['preview']['impacts'])): ?>
              <div class="impacts"><b>Impacts:</b><?=render_list($result['preview']['impacts'])?></div>
            <?php endif; ?>
            <?php if (!empty($result['preview']['risk_warnings'])): ?>
              <div class="warnings"><b>Risk Warnings:</b><?=render_list($result['preview']['risk_warnings'])?></div>
            <?php endif; ?>
          </div>
          <form method="post" style="margin-top:1em;">
            <input type="hidden" name="csrf" value="<?=$csrf?>">
            <input type="hidden" name="action" value="apply_nl">
            <input type="hidden" name="provider" value="<?=esc($_POST['provider'])?>">
            <input type="hidden" name="proposal_json" value="<?=esc(json_encode($result['proposal']))?>">
            <button type="button" onclick="showApplyModal('apply_nl')">Apply Changes</button>
          </form>
          <script>
            function showApplyModal(action) {
              var form = document.querySelector('form[action="apply_nl"]');
              var proposal = JSON.parse(document.querySelector('input[name="proposal_json"]').value);
              var x = new XMLHttpRequest();
              x.open('POST', '', true);
              x.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
              x.onload = function() {
                // Modal is injected server-side
                document.body.insertAdjacentHTML('beforeend', x.responseText);
              };
              x.send('csrf=<?=$csrf?>&fetch_apply_modal=1&action='+action+'&proposal_json='+encodeURIComponent(JSON.stringify(proposal)));
            }
          </script>
        <?php endif; ?>
      </div>
    </div>
    <!-- Analyze Tab -->
    <div class="tabcontent<?= $tab==='analyze'?' active':'' ?>" id="tab-analyze">
      <div class="panel">
        <h2>Analyze Rules</h2>
        <form method="post">
          <input type="hidden" name="csrf" value="<?=$csrf?>">
          <input type="hidden" name="action" value="analyze_rules">
          <button type="submit">Analyze Rules</button>
        </form>
        <?php if ($report): ?>
          <div>
            <h3>Report</h3>
            <pre><?=esc($report['text'] ?? '')?></pre>
            <h4>Preview</h4>
            <pre><?=esc(AIPlanRenderer::render_preview($report['proposal'])['text'] ?? '')?></pre>
            <h4>Diff</h4>
            <pre><?=esc(AIPlanRenderer::render_preview($report['proposal'])['diff'] ?? '')?></pre>
          </div>
          <form method="post" style="margin-top:1em;">
            <input type="hidden" name="csrf" value="<?=$csrf?>">
            <input type="hidden" name="action" value="apply_analysis">
            <input type="hidden" name="proposal_json" value="<?=esc(json_encode($report['proposal']))?>">
            <button type="button" onclick="showApplyModal('apply_analysis')">Apply Changes</button>
          </form>
        <?php endif; ?>
      </div>
    </div>
    <!-- Wizards Tab -->
    <div class="tabcontent<?= $tab==='wizards'?' active':'' ?>" id="tab-wizards">
      <div class="panel">
        <h2>Guided Wizards</h2>
        <form method="post" style="margin-bottom:1em;">
          <input type="hidden" name="csrf" value="<?=$csrf?>">
          <input type="hidden" name="action" value="wizard_start">
          <label for="wiz_type">Wizard type:</label>
          <select name="wiz_type" id="wiz_type">
            <option value="ha">High Availability (CARP/pfsync/XMLRPC)</option>
            <option value="multiwan">Multi-WAN</option>
            <option value="vpn">VPN (OpenVPN/IPsec)</option>
          </select>
          <button type="submit">Start Wizard</button>
        </form>
        <?php
          $wizard_state = $_SESSION['ai_wizard_state'] ?? null;
          $wizard_questions = $_SESSION['ai_wizard_questions'] ?? [];
          $wizard_proposal_json = $_SESSION['ai_wizard_proposal_json'] ?? null;
          if ($wizard_questions) {
            echo "<form method='post'><input type='hidden' name='csrf' value='$csrf'><input type='hidden' name='action' value='wizard_next'>";
            foreach ($wizard_questions as $k=>$q) {
              echo "<label for='answer_$k'>" . esc($q) . "</label>";
              echo "<input type='text' name='answer_$k' id='answer_$k'>";
            }
            echo "<button type='submit'>Next</button></form>";
          }
          if ($wizard_proposal_json) {
            $wizard_proposal = json_decode($wizard_proposal_json, true);
            echo "<div><h3>Proposal Preview</h3>";
            $preview = AIPlanRenderer::render_preview($wizard_proposal);
            echo "<pre>" . esc($preview['text']) . "</pre>";
            echo "<pre>" . esc($preview['diff']) . "</pre>";
            echo "</div>";
            echo "<form method='post'><input type='hidden' name='csrf' value='$csrf'><input type='hidden' name='action' value='wizard_apply'><input type='hidden' name='proposal_json' value='" . esc(json_encode($wizard_proposal)) . "'><button type='button' onclick=\"showApplyModal('wizard_apply')\">Apply Changes</button></form>";
          }
        ?>
      </div>
    </div>
  </div>
  <?php
    // If JS triggers modal fetch, respond inline
    if ($_SERVER['REQUEST_METHOD'] === 'POST' && !empty($_POST['fetch_apply_modal'])) {
      $proposal = json_decode($_POST['proposal_json'] ?? '', true);
      if ($proposal) {
        $validate = AIApplyEngine::validateProposal($proposal);
        $action = $_POST['action'] ?? '';
        render_apply_modal($proposal, $validate, $csrf, $action, []);
        exit;
      }
    }
  ?>
</section>
<?php include("foot.inc"); ?>