<?php if (!isset($visualDashboardRole)) return; $welcomeAdmin = $visualDashboardRole === 'admin'; ?>
<style>
.welcome-panel{position:relative;isolation:isolate;overflow:hidden;display:flex;align-items:center;justify-content:space-between;gap:24px;padding:30px 34px;margin-bottom:24px;border:1px solid #244568;border-radius:14px;background:linear-gradient(115deg,#0b213e,#102e52 65%,#0b1c32);color:#eaf3ff}
.welcome-copy{max-width:620px}.welcome-kicker{font-size:11px;font-weight:700;letter-spacing:2px;color:#69c8ff}.welcome-panel h2{font-size:25px;line-height:1.3;margin:10px 0}.welcome-panel p{font-size:14px;line-height:1.8;color:#b8cde4;margin:0 0 18px}.welcome-action{display:inline-block;background:#2563eb;border:1px solid #4d8af4;padding:11px 17px;border-radius:7px;color:#fff!important;text-decoration:none;font-size:13px;font-weight:700}.welcome-art{width:260px;height:155px;flex-shrink:0}.chart-scope{font-size:12px;color:#9eb5ce;line-height:1.7;margin:0 0 16px}
@media(max-width:1050px){.welcome-art{width:180px}.welcome-panel{padding:24px}}@media(max-width:650px){.welcome-art{display:none}.welcome-panel h2{font-size:21px}}
</style>
<section class="welcome-panel" aria-label="Welcome to your dashboard">
<div class="welcome-copy"><span class="welcome-kicker">YOUR SECURITY WORKSPACE</span>
<h2><?= $welcomeAdmin ? 'Keep your security operations in view.' : 'Welcome back. See how your scans are progressing.' ?></h2>
<p><?= $welcomeAdmin ? 'Explore scanning trends, review pending accounts and manage the rules behind your analysis.' : 'Track failed checks, explore severity trends and open your recent scans to review the code that needs attention.' ?></p>
<a class="welcome-action" href="<?= $welcomeAdmin ? '../ManageUser/user.php' : '../Engine_Process/index.php' ?>"><?= $welcomeAdmin ? 'Review users' : 'Start a new scan' ?> &rarr;</a>
</div>
<svg class="welcome-art" viewBox="0 0 260 155" fill="none" aria-hidden="true">
<rect x="10" y="10" width="230" height="133" rx="12" fill="#081a30" stroke="#345777"/>
<circle cx="27" cy="25" r="3" fill="#5bbcff"/><circle cx="38" cy="25" r="3" fill="#3d759e"/>
<path d="M27 115H145M27 90H145M27 65H145" stroke="#1e3a55"/>
<path d="M28 111L49 96L69 101L90 72L112 81L140 48" stroke="#58b6ff" stroke-width="4" stroke-linecap="round" stroke-linejoin="round"/>
<circle cx="191" cy="82" r="29" stroke="#193b5b" stroke-width="13"/>
<circle cx="191" cy="82" r="29" stroke="#4f8cff" stroke-width="13" stroke-dasharray="105 183" transform="rotate(-90 191 82)"/>
<circle cx="191" cy="82" r="29" stroke="#37d7b0" stroke-width="13" stroke-dasharray="45 183" transform="rotate(120 191 82)"/>
</svg></section>
<p class="chart-scope">Charts use recorded scan data. Severity charts count FAIL checks only; repeated scans may count the same issue again. A zero count does not establish that the code is secure.</p>
