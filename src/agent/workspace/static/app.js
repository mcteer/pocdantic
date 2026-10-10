'use strict';
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
  interrupted: 'Task stopped. Inspect cleanup before starting another task.'
};
let session = null, latestJobs = [], currentId = null, pending = null, pendingRetry = null;
let posting = false, knownBusy = false, lastPoll = 0, polling = false;

function showError(error) {
  $('error').textContent = messages[error?.code] ||
    'Connection failed. Check the existing submission before starting another task.';
  $('error').hidden = false;
  $('error').focus();
}

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

async function loadSession() {
  session = await api('/workspace/session');
  $('login').disabled = false;
  $('session-status').textContent = session.signed_in ? 'Signed in' : 'Sign in to run a task';
  $('login').hidden = session.signed_in;
  $('logout').hidden = !session.signed_in;
  $('workspace').hidden = !session.signed_in;
  $('profile').replaceChildren(...session.profiles.map(profile => {
    const option = document.createElement('option');
    option.value = profile;
    option.textContent = profile;
    return option;
  }));
  $('issues').textContent = session.configuration_issues.length ?
    'Optional integrations need configuration: ' + session.configuration_issues.join(', ') : '';
  if (session.login_error) showError(session.login_error);
}

function controls(busy) {
  $('run').disabled = posting || busy;
  $('task').disabled = posting || !!pending;
  $('profile').disabled = posting || !!pending;
  $('retry').disabled = posting || busy;
  $('run').textContent = pending ? 'Check submission' : 'Run';
}

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
  $('action').textContent = job.action_summary || '';
  $('result').textContent = (job.result || '') + (job.truncated ? '\n[Result truncated]' : '');
  $('retry').hidden = !job.retry_available;
  $('error').hidden = !job.error;
  if (job.error) $('error').textContent = messages[job.error.code] || messages.task_failed;
}

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

async function poll() {
  if (!session?.signed_in || polling || Date.now() - lastPoll < 1000) return;
  lastPoll = Date.now();
  polling = true;
  try {
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

async function pollLoop() {
  await poll();
  const delay = session?.signed_in ? Math.max(1, 1000 - (Date.now() - lastPoll)) : 1000;
  setTimeout(pollLoop, delay);
}

$('login').addEventListener('click', async () => {
  $('login').disabled = true;
  try {
    const data = await api('/auth/login', {schema_version: 1});
    location.assign(data.authorization_url);
  } catch (error) {
    showError(error);
    $('login').disabled = false;
  }
});

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

loadSession().then(poll).catch(showError);
pollLoop();
