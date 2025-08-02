<?php
/*
 * attack.inc
 * MITRE ATT&CK mapping for pfSense AI
 */
$ATTACK_MAP = [
    'ssh brute force' => ['tactic'=>'Credential Access','technique'=>'Brute Force','id'=>'T1110.003'],
    'rdp brute force' => ['tactic'=>'Credential Access','technique'=>'Brute Force','id'=>'T1110.001'],
    'sql injection'   => ['tactic'=>'Initial Access','technique'=>'Exploit Public-Facing Application','id'=>'T1190'],
    'dns tunnel'      => ['tactic'=>'Command and Control','technique'=>'Application Layer Protocol','id'=>'T1071.004'],
    'ldap enumeration'=> ['tactic'=>'Discovery','technique'=>'Account Discovery','id'=>'T1087.002'],
    'port scan'       => ['tactic'=>'Reconnaissance','technique'=>'Active Scanning','id'=>'T1595'],
    'malware download'=> ['tactic'=>'Execution','technique'=>'User Execution','id'=>'T1204.002'],
];

function attack_map($msg) {
    global $ATTACK_MAP;
    $msg_lc = strtolower($msg);
    foreach ($ATTACK_MAP as $k => $v) {
        if (strpos($msg_lc, $k) !== false) {
            return $v + ['matched'=>$k];
        }
    }
    return null;
}