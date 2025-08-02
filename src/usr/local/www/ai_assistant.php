&lt;?php
/*
 * ai_assistant.php
 * pfSense AI Assistant - Chat-style interface
 */
require_once("guiconfig.inc");
require_once("/etc/inc/ai.inc");

$voice_enabled = $config['system']['ai']['voice_enable'] ?? false;

include("head.inc");
?&gt;

&lt;div class="container-fluid"&gt;
  &lt;div class="row"&gt;
    &lt;div class="col-md-8 col-md-offset-2"&gt;
      &lt;div class="card"&gt;
        &lt;div class="card-header bg-primary text-white"&gt;
          &lt;h3&gt;AI Assistant&lt;/h3&gt;
        &lt;/div&gt;
        &lt;div class="card-body" id="chat-history" style="height:400px; overflow-y:auto; background:#fcfcfc; border:1px solid #e0e0e0;"&gt;
          &lt;!-- Chat messages appear here --&gt;
        &lt;/div&gt;
        &lt;form id="chat-form" onsubmit="return false;" class="mt-2"&gt;
          &lt;div class="input-group"&gt;
            &lt;input type="text" id="user-input" class="form-control" placeholder="Type your message..." autocomplete="off" autofocus&gt;
            &lt;span class="input-group-btn"&gt;
              &lt;button class="btn btn-success" type="button" onclick="sendMessage()"&gt;Send&lt;/button&gt;
              &lt;button class="btn btn-default" type="button" id="mic-btn"&gt;&lt;i class="fa fa-microphone"&gt;&lt;/i&gt;&lt;/button&gt;
            &lt;/span&gt;
          &lt;/div&gt;
        &lt;/form&gt;
      &lt;/div&gt;
    &lt;/div&gt;
  &lt;/div&gt;
&lt;/div&gt;

<script src="/js/jquery.min.js"></script>
<script>
let voiceEnabled = <?= $voice_enabled ? 'true' : 'false' ?>;
let recognition, recognizing = false;

// Web Speech API setup
if ('webkitSpeechRecognition' in window) {
  recognition = new webkitSpeechRecognition();
  recognition.continuous = false;
  recognition.interimResults = false;
  recognition.lang = "en-US";
  recognition.onresult = function(e) {
    let transcript = e.results[0][0].transcript;
    document.getElementById('user-input').value = transcript;
    sendMessage();
  };
  recognition.onend = function() { recognizing = false; };
  $('#mic-btn').click(function() {
    if (!recognizing) {
      recognition.start();
      recognizing = true;
      $('#mic-btn').addClass('btn-danger');
    } else {
      recognition.stop();
      recognizing = false;
      $('#mic-btn').removeClass('btn-danger');
    }
  });
} else {
  // Hide mic button if not supported
  $('#mic-btn').hide();
}

function appendMessage(sender, text) {
  let html = '<div class="mb-2"><strong>'+sender+'</strong>: '+text+'</div>';
  $('#chat-history').append(html);
  $('#chat-history').scrollTop($('#chat-history')[0].scrollHeight);
}

function speak(text) {
  if (voiceEnabled && 'speechSynthesis' in window) {
    let utter = new SpeechSynthesisUtterance(text);
    utter.lang = "en-US";
    speechSynthesis.speak(utter);
  }
}

function sendMessage() {
  let msg = $('#user-input').val().trim();
  if (!msg) return;
  appendMessage('You', msg);
  $('#user-input').val('');
  fetch('/api/ai_chat.php', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({
      message: msg,
      system: <?= json_encode($system_prompt) ?>
    }),
    credentials: 'same-origin'
  })
  .then(res => res.json())
  .then(data => {
    appendMessage('AI', data.reply);
    speak(data.reply);
    // IDS/IPS action toast
    if (data.action && (data.action === 'enable' || data.action === 'disable' || data.action === 'add')) {
      if (data.success) {
        alert("Success: " + data.reply);
      } else {
        alert("Failed: " + data.reply);
      }
    }
  })
  .catch(() => {
    appendMessage('AI', '[Error: No response]');
  });
}

// SSE event stream for block/unblock toasts
if (!!window.EventSource) {
  const evtSrc = new EventSource('/api/ai_events.php');
  evtSrc.addEventListener('block', function(e) {
    var data = JSON.parse(e.data);
    alert("AI blocked IP " + data.ip + ": " + data.reason);
  });
  evtSrc.addEventListener('unblock', function(e) {
    var data = JSON.parse(e.data);
    alert("AI unblocked IP " + data.ip);
  });
}
</script>

<?php
/*
 * ai_assistant.php
 * pfSense AI Assistant - Chat-style interface
 */
require_once("guiconfig.inc");
require_once("/etc/inc/ai.inc");

$voice_enabled = $config['system']['ai']['voice_enable'] ?? false;
$system_prompt = 'If you wish to enable/disable/add IDS/IPS rules, reply only with a valid JSON object: {"target":"snort|suricata","action":"enable|disable|add","sid":SID,"rule":"<text>","message":"..."}';

include("head.inc");
?> include("foot.inc"); ?>