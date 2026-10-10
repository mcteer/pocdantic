/* Local workspace UI: credentials stay on the server behind an HttpOnly cookie.
 * Session/CSRF state and uncertain submissions live only in this page's memory.
 * Requests never automatically replay effects; polling only reads public job views.
 */
'use strict';
// Resolve fixed element IDs; provider/task text is rendered with textContent below.
const $ = id => document.getElementById(id);
const terminal = new Set(['completed', 'denied', 'failed', 'interrupted']);
const messages = {
  sign_in_required: 'Select Sign in again.',
  login_cancelled: 'Sign-in was cancelled. Select Sign in to try again.',
  login_invalid: 'Sign-in could not be verified. Start a new sign-in.',
  identity_unavailable: 'Identity service unavailable. Try Sign in later.',
  token_lifetime_short: 'Increase provider token lifetime or reduce TIMEOUT_SECONDS, then sign in.',
  configuration_missing: 'Configure the missing setting or install the required extra.',
  invalid_request: 'Check the task and selected profile.',
  request_forbidden: 'Open the printed local workspace URL and reload.',
  submission_conflict: 'Use a new submission for changed task text.',
  workspace_busy: 'Wait for the current task and cleanup to finish.',
  capacity_exceeded: 'Finish active work, then sign out and sign in again.',
  run_not_found: 'Reload the run list for this session.',
  workspace_unavailable: 'Cleanup is unresolved. Check cleanup before restarting the workspace.',
  profile_unavailable: 'Select a profile with the needed capability.',
  model_unavailable: 'Check the selected model provider configuration.',
  task_failed: 'Review the failed stage before starting another task.',
  policy_denied: 'Check the granted resource scope and profile. Database reads need database:read and database-reader.',
  database_unavailable: 'Check database and delegated credential configuration.',
  approval_denied: 'The requested action was denied.',
  approval_unconfirmed: 'No confirmed phone decision. Retry approval is available only when safe.',
  approval_invalid: 'Approval binding could not be verified. Check configuration.',
  approval_unavailable: 'Configure and enable the phone integration.',
  retry_unavailable: 'This attempt cannot be retried.',
  cleanup_failed: 'Credential cleanup failed. Resolve it before another attempt.',
  interrupted: 'Task stopped. Inspect cleanup before starting another task.',
  dependency_unreachable: 'The configured service could not be reached. Check its host, port, network, and provider status.',
  diagnostic_timeout: 'The check timed out. Check provider status and network configuration; no root cause is confirmed.',
  provider_access_denied: 'The provider denied access. Ask its administrator to verify the configured permissions. Recovery is separate.',
  acquisition_uncertain: 'Credential issuance is uncertain. An operator must obtain exact native evidence; a healthy connection does not clear it.',
  cleanup_unconfirmed: 'Credential cleanup is unconfirmed. An operator must revoke the exact recorded lease.',
  recovery_uninitialized: 'Before first live database use, run uv run agent recover init. Enrollment tracks future attempts only; it does not repair incidents.',
  recovery_storage_error: 'Recovery storage is unsafe or damaged. Preserve its files; ask the operator to investigate or restore a matching private backup. Do not delete or reinitialize it.',
  recovery_environment_mismatch: 'Recovery state belongs to different configuration. Restore the original configuration; do not create an empty journal.',
  recovery_evidence_required: 'Exact native request/response evidence or a known lease is missing. Ask the operator for the matching audit export; unavailable evidence leaves recovery blocked.',
  recovery_evidence_invalid: 'Recovery evidence did not match this incident. The operator must inspect exact linkage and review.',
  recovery_access_denied: 'The operator needs authority to revoke this exact lease with synchronous completion.',
  recovery_busy: 'An active task or cleanup owns recovery. Wait for it to finish.',
  recovery_capacity: 'Recovery storage is full. Resolve recorded incidents; unresolved records are never discarded.',
  response_uninitialized: 'An operator must run agent respond init --prepare, review the private policy, then agent respond init.',
  response_migration_required: 'Stop live work and run agent recover migrate before response enrollment.',
  recovery_migration_required: 'Stop live work and run agent recover migrate before new database reads.',
  response_storage_error: 'Containment storage needs operator repair. Preserve its files; do not reset it.',
  response_policy_changed: 'Restore the enrolled configuration. Editing policy does not clear a hold.',
  contained: 'Work stopped by an incident. An operator must confirm credential cleanup before release.',
  response_busy: 'The response owner is draining. Wait and inspect incident status.',
  response_capacity: 'The incident queue is full. An operator must resolve recorded incidents.',
  diagnostics_busy: 'A previous connection check is still running or draining. Wait for it to finish.'
};
let session = null, latestJobs = [], currentId = null, pending = null, pendingRetry = null;
let posting = false, knownBusy = false, lastPoll = 0, polling = false;
let operational = null, diagnosticReport = null, checking = false, authPosting = false;

/** Show a closed error message and move keyboard focus to its accessible container. */
function showError(error) {
  $('error').textContent = messages[error?.code] ||
    'Connection failed. Check the existing submission before starting another task.';
  $('error').hidden = false;
  $('error').focus();
}

/** Call the same-origin API without caching; a body selects a CSRF-protected POST.
 * Throw the server's safe error projection, keeping transport failures distinguishable
 * from an explicit rejection. A 204 response has no JSON body. */
async function api(path, body) {
  const options = {credentials: 'same-origin', cache: 'no-store'};
  if (body) {
    options.method = 'POST';
    options.headers = {'Content-Type': 'application/json', 'X-CSRF-Token': session?.csrf_token || ''};
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const data = response.status === 204 ? null : await response.json();
  if (!response.ok) throw data?.error || {code: 'task_failed'};
  return data;
}

/** Load the server-held session projection and bootstrap CSRF state before enabling login.
 * Render configuration names and profile options as text, never provider credentials. */
async function loadSession() {
  session = await api('/workspace/session');
  $('login').disabled = authPosting;
  $('session-status').textContent = session.signed_in ? 'Signed in' : 'Sign in to run a task';
  $('login').hidden = session.signed_in;
  $('logout').hidden = !session.signed_in;
  $('workspace').hidden = !session.signed_in;
  // Remove owned provider details when logout, expiry or suspension closes the session.
  if (!session.signed_in) $('provider-controls').replaceChildren();
  $('profile').replaceChildren(...session.profiles.map(profile => {
    const option = document.createElement('option');
    option.value = profile;
    option.textContent = profile;
    return option;
  }));
  $('issues').textContent = session.configuration_issues.length ?
    'Optional integrations need configuration: ' + session.configuration_issues.join(', ') : '';
  if (session.login_error) showError(session.login_error);
  await loadOperations();
  diagnosticFreshness();
}

/** Disable conflicting operations and freeze the exact payload of an uncertain submission.
 * "Check submission" resends the same UUID/body for server-side deduplication. */
function controls(busy) {
  const blocked = operational && (!['clear', 'not_configured'].includes(operational.recovery) || operational.containment?.restricted);
  $('run').disabled = posting || busy || blocked;
  $('task').disabled = posting || !!pending;
  $('profile').disabled = posting || !!pending;
  $('retry').disabled = posting || busy || blocked;
  $('run').textContent = pending ? 'Check submission' : 'Run';
}

/** Display one public job view using textContent so task/model output cannot inject HTML.
 * Retry availability is decided by trusted server checks, not inferred from UI labels. */
function render(job) {
  currentId = job.job_id;
  const labels = {
    accepted: 'Accepted', running: 'Running', waiting_for_approval: 'Waiting for your phone decision',
    cleaning_up: 'Cleaning up credentials', completed: 'Completed', denied: 'Denied',
    failed: 'Failed', interrupted: 'Interrupted'
  };
  $('status').textContent = labels[job.state] +
    (job.approval_status === 'unconfirmed' ? ' — approval unconfirmed' : '');
  $('correlation').textContent = 'Job ' + job.job_id + ' · Request ' + job.request_id +
    ' · Run ' + (job.run_id || 'pending');
  $('cleanup').textContent = 'Credential cleanup: ' + job.cleanup_status;
  const containment = job.containment || [];
  $('containment-status').textContent = containment.length ? containment.map(item =>
    (item.contained ? 'Work stopped' : 'Local hold released') + ' · Credential cleanup ' +
    (item.cleanup === 'confirmed' ? 'confirmed' : item.cleanup === 'not_applicable' ? 'not applicable' : 'pending')
  ).join(' · ') : '';
  // Outcomes are session-owned closed projections; never render native target metadata.
  const labelsByControl = {
    block_registration: 'Workload registration', revoke_native_token: 'Native service token',
    suspend_user: 'Tenant user suspension', revoke_user_sessions: 'Tenant login sessions',
    rotate_static: 'Isolated password rotation', terminate_static_sessions: 'Isolated database sessions',
    notify_teams: 'Teams notice'
  };
  $('provider-controls').replaceChildren(...containment.flatMap(item =>
    [...(item.provider_controls || []).map(control => {
      const row = document.createElement('li');
      const paths = Object.entries(control.paths || {}).map(([path, result]) =>
        path.replaceAll('_', ' ') + ': ' + result.replaceAll('_', ' ')).join('; ');
      row.textContent = labelsByControl[control.kind] + ' — request ' + control.state +
        '. Independent checks: ' + paths +
        (control.provenance === 'synthetic' ? '. Synthetic evidence only.' : '');
      return row;
    }), ...Object.entries(item.database_checks || {}).map(([path, result]) => {
      const row = document.createElement('li');
      row.textContent = (path === 'dynamic_fresh' ? 'Dynamic database login' : 'Held database session') +
        ' — independent check: ' + result.replaceAll('_', ' ');
      return row;
    })]
  ));
  $('action').textContent = job.action_summary || '';
  $('result').textContent = (job.result || '') + (job.truncated ? '\n[Result truncated]' : '');
  $('retry').hidden = !job.retry_available;
  $('error').hidden = !job.error;
  if (job.error) $('error').textContent = messages[job.error.code] || messages.task_failed;
}

/** Update history in place, reusing buttons to preserve keyboard focus during polling.
 * Click handlers resolve the latest job view rather than retaining an old response. */
function history(jobs) {
  const existing = new Map([...$('history').children].map(li => [li.dataset.jobId, li]));
  let previous = null;
  for (const job of jobs) {
    let li = existing.get(job.job_id);
    if (!li) {
      li = document.createElement('li');
      li.dataset.jobId = job.job_id;
      const button = document.createElement('button');
      button.addEventListener('click', () => {
        const current = latestJobs.find(value => value.job_id === li.dataset.jobId);
        if (current) render(current);
      });
      li.append(button);
    }
    const position = previous ? previous.nextSibling : $('history').firstChild;
    if (position !== li) $('history').insertBefore(li, position);
    previous = li;
    li.firstChild.textContent = job.kind + ' · ' + job.state + ' · ' + job.job_id;
  }
}

/** Read session-owned jobs at most once per second with no overlapping requests.
 * Refresh the session projection after expiry; do not submit or retry effects here. */
async function poll() {
  if (!session || polling || Date.now() - lastPoll < 1000) return;
  lastPoll = Date.now();
  polling = true;
  try {
    await loadOperations();
    diagnosticFreshness();
    if (!session.signed_in) return;
    latestJobs = (await api('/workspace/runs')).jobs;
    knownBusy = latestJobs.some(job => !terminal.has(job.state));
    history(latestJobs);
    const selected = latestJobs.find(job => job.job_id === currentId) || latestJobs[0];
    if (selected) render(selected);
    controls(knownBusy);
  } catch (error) {
    if (error.code === 'sign_in_required') await loadSession();
    else showError(error);
  } finally {
    polling = false;
  }
}

/** Schedule the next read after the previous poll settles, including when signed out. */
async function pollLoop() {
  await poll();
  const delay = session?.signed_in ? Math.max(1, 1000 - (Date.now() - lastPoll)) : 1000;
  setTimeout(pollLoop, delay);
}

// Start a bound login attempt, then navigate to its trusted authorization URL.
$('login').addEventListener('click', async () => {
  authPosting = true;
  $('login').disabled = true;
  try {
    const data = await api('/auth/login', {schema_version: 1});
    location.assign(data.authorization_url);
  } catch (error) {
    showError(error);
    authPosting = false;
    $('login').disabled = false;
  }
});

// Clear page-held tasks/results only after the server has accepted session closure.
$('logout').addEventListener('click', async () => {
  try {
    await api('/auth/logout', {schema_version: 1});
    pending = null;
    pendingRetry = null;
    currentId = null;
    latestJobs = [];
    knownBusy = false;
    $('task').value = '';
    $('result').textContent = '';
    $('history').replaceChildren();
    await loadSession();
  } catch (error) { showError(error); }
});

// Allocate one submission UUID and retain its exact body while delivery is uncertain.
// An explicit server rejection releases it; a network failure requires a manual check.
$('task-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (posting) return;
  if (!pending) pending = {
    schema_version: 1, submission_id: crypto.randomUUID(),
    task: $('task').value, profile: $('profile').value
  };
  posting = true;
  controls(knownBusy);
  $('error').hidden = true;
  try {
    const job = await api('/workspace/runs', pending);
    pending = null;
    knownBusy = !terminal.has(job.state);
    render(job);
    $('result-heading').focus();
  } catch (error) {
    // Uncertain delivery retains the exact UUID and body; no automatic effect retry.
    if (error.code) pending = null;
    showError(error);
  } finally {
    posting = false;
    controls(knownBusy);
    await poll();
  }
});

// Approval retry has its own UUID and bound parent. The server rechecks the exact
// action and identity; this request does not replay the original model/task execution.
$('retry').addEventListener('click', async () => {
  if (posting || !currentId) return;
  if (!pendingRetry) pendingRetry = {
    parent: currentId, body: {schema_version: 1, submission_id: crypto.randomUUID()}
  };
  posting = true;
  controls(knownBusy);
  $('error').hidden = true;
  try {
    const job = await api('/workspace/runs/' + pendingRetry.parent + '/retry', pendingRetry.body);
    pendingRetry = null;
    knownBusy = !terminal.has(job.state);
    render(job);
    $('result-heading').focus();
  } catch (error) {
    if (error.code) pendingRetry = null;
    showError(error);
  } finally {
    posting = false;
    controls(knownBusy);
    await poll();
  }
});




/** Display separate sign-in, connection, and recovery states; never infer cleanup from health. */
function renderOperations(view) {
  operational = view;
  $('operations-status').textContent =
    'Sign-in: ' + (view.authentication ? 'signed in' : 'sign-in required') +
    ' · Connection: ' + view.connection + ' · Recovery: ' + view.recovery.replaceAll('_', ' ') +
    (view.blocked_count ? ' (' + view.blocked_count + ' unresolved)' : '') +
    (view.active_work ? ' · Work active' : '') +
    (view.containment?.restricted ? ' · Work stopped by an incident' : '');
  $('recovery-guidance').textContent = view.reason_code ? messages[view.reason_code] || '' :
    'Connection checks do not start tasks or change sign-in. Recovery never replays an earlier task.';
  $('incidents').replaceChildren(...view.incidents.map(incident => {
    const li = document.createElement('li');
    const command = incident.next_action === 'recover_exact_lease' ?
      'uv run agent recover revoke --incident ' + incident.incident_id :
      'uv run agent recover status';
    li.textContent = 'Incident ' + incident.incident_id + ' · ' + incident.stage + ': ' +
      messages[incident.reason_code] + ' Operator command: ' + command;
    return li;
  }));
  if (view.blocked_count && !view.incidents.length) {
    $('recovery-guidance').textContent += ' Operator: run uv run agent recover status to list incident references.';
  }
  $('check-connection').disabled = !session || checking;
  $('check-recovery').disabled = !session || checking;
  $('login').disabled = authPosting || view.active_work;
  controls(knownBusy || view.active_work || view.containment?.restricted);
}

/** Reread only local aggregate status; polling never runs a provider diagnostic or recovery effect. */
async function loadOperations() {
  renderOperations(await api('/workspace/operations'));
}

/** Mark old observations stale without performing another provider request. */
function diagnosticFreshness() {
  if (!diagnosticReport) return;
  const stale = Date.now() - Date.parse(diagnosticReport.finished_at) > 60000;
  $('diagnostic-freshness').textContent = stale ?
    'Connection observations are stale. Select Check connection for a new check.' :
    'Connection observations checked just now; transport checks do not prove authorization or cleanup.';
}

/** Render fixed observations as text. Provider bodies and target addresses never reach this view. */
function renderDiagnostics(report) {
  diagnosticReport = report;
  const observed = {
    configuration: 'Local configuration checks passed.',
    identity: 'Public identity discovery responded; user authorization was not tested.',
    vault: 'Vault reports unsealed; credential issuance permission was not tested.',
    database: 'Database TCP connection succeeded (transport only; no authentication).',
    sign_in: 'The current session is signed in.', recovery: 'No recovery block was reported.'
  };
  $('diagnostic-checks').replaceChildren(...report.checks.map(check => {
    const li = document.createElement('li');
    li.textContent = check.check_id + ' · ' + check.category + ' · ' + check.state + ': ' +
      (check.reason_code ? messages[check.reason_code] : check.state === 'observed' ?
        observed[check.check_id] : 'The check was inconclusive; no root cause is confirmed.');
    return li;
  }));
  diagnosticFreshness();
}

// Both checks require completed cookie/CSRF bootstrap and never submit or replay a task.
$('check-connection').addEventListener('click', async () => {
  if (!session || checking) return;
  checking = true;
  renderOperations(operational);
  try {
    renderDiagnostics(await api('/workspace/diagnostics', {schema_version: 1}));
    await loadOperations();
  } catch (error) { showError(error); }
  finally { checking = false; if (operational) renderOperations(operational); }
});

$('check-recovery').addEventListener('click', async () => {
  if (!session || checking) return;
  checking = true;
  renderOperations(operational);
  try {
    renderOperations(await api('/workspace/recovery/check', {schema_version: 1}));
  } catch (error) { showError(error); }
  finally { checking = false; if (operational) renderOperations(operational); }
});

// Bootstrap cookie/CSRF before enabling any control; subsequent polling is read-only.
loadSession().then(poll).catch(showError);
pollLoop();
