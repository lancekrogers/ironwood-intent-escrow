import {validateReport, summary} from './report.mjs';
const $ = id => document.getElementById(id);
const REPO = 'https://github.com/lancekrogers/ironwood-intent-escrow';
let config;
let downloadURL;
const labels = {
  'near payment recorded':'Stored NEAR receipt matches its recorded hash',
  'near payment fetched':'NEAR archival node returns the recorded payment',
  'near payment attests':'NEAR payment satisfies the quote and passes the privacy filter',
  'refund address absent':'Refund address absent from quotes and fill evidence',
  'policy outcomes recorded':'Records report deadline and paid-quote refusals',
  'broadcast sent':'Records report successful broadcasts and mined heights',
};
function label(name) {
  if (labels[name]) return labels[name];
  const [file, check] = name.split(' ');
  const title = {'fill.fund.tx':'Fill funding', 'fill.spend.tx':'Solver release', 'refund.fund.tx':'Refund funding', 'refund.spend.tx':'Refund payment'}[file];
  return `${title}: ${{txid:'stored bytes match the transaction ID', fetched:'node bytes and mined height match', check_zec:'no transparent transfer or zero outgoing viewing key'}[check]}`;
}
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function link(text, href) {
  const node = element('a', text); node.href = href;
  node.target = '_blank'; node.rel = 'noopener noreferrer'; return node;
}
function setStatus(state, title, detail) {
  $('status').className = `status ${state}`;
  $('status').querySelector('.status-symbol').textContent = ({passed:'✓',failed:'×',unavailable:'!',stale:'◷'})[state] || '○';
  $('status-title').textContent = title;
  $('status-detail').textContent = detail;
}
function clearReport() {
  $('results').replaceChildren(); $('report-meta').replaceChildren(); $('report-meta').hidden = true;
  $('report-download').hidden = true;
  if (downloadURL) { URL.revokeObjectURL(downloadURL); downloadURL = null; }
}
function renderReport(report) {
  const status = summary(report); setStatus(status.state, status.title, status.detail);
  const meta = $('report-meta'); meta.hidden = false;
  const stamp = element('time', `Checked ${new Date(report.checked_at).toLocaleString()} (your local time)`); stamp.dateTime = report.checked_at;
  meta.append(stamp, link(`Source ${report.commit.slice(0,7)} ↗`, `${REPO}/commit/${report.commit}`));
  if (report.run_url && /^https:\/\/github\.com\/lancekrogers\/ironwood-intent-escrow\/actions\/runs\/\d+$/.test(report.run_url)) meta.append(link('Verification run ↗', report.run_url));
  const groups = [
    ['network','Public node responses','Live when this report was generated: fetched bytes and mined heights are compared with the committed records.'],
    ['validation','Transaction and receipt validation','Checks performed by the existing Rust verifier on the fetched and committed data.'],
    ['recorded','Recorded signer outcomes','Assertions from the completed run records. This click does not repeat FROST signing or independently prove these decisions.'],
  ];
  for (const [scope,title,description] of groups) {
    const checks = report.checks.filter(check => check.scope === scope);
    if (!checks.length) continue;
    const section = element('section', undefined, 'check-group');
    section.append(element('h3',title),element('p',description));
    for (const check of checks) {
      const row = element('div',undefined,'check-row');
      const text = element('div',label(check.name));
      text.append(element('span', check.detail || check.name, 'check-description'));
      row.append(element('span',check.status.toUpperCase(),`check-state ${check.status}`),text); section.append(row);
    }
    $('results').append(section);
  }
  downloadURL = URL.createObjectURL(new Blob([JSON.stringify(report,null,2)], {type:'application/json'}));
  $('report-download').href = downloadURL; $('report-download').download = 'ironwood-verification.json'; $('report-download').hidden = false;
}
async function json(url, timeout = 20000) {
  const response = await fetch(url, {cache:'no-store', signal:AbortSignal.timeout(timeout)});
  if (!response.ok) throw new Error(`Request failed (HTTP ${response.status}).`);
  return response.json();
}
async function verify() {
  const button = $('verify-button'); button.disabled = true; clearReport();
  setStatus('neutral', config.mode === 'live' ? 'Checking public testnet nodes…' : 'Loading the latest published verification…', config.mode === 'live' ? 'The server is running the read-only Rust verifier. This can take up to three minutes.' : 'This retrieves a timestamped report; it does not start a new chain check.');
  try {
    const report = validateReport(await json(config.report_url, config.mode === 'live' ? 200000 : 20000));
    renderReport(report);
  } catch (error) {
    setStatus('unavailable','Could not retrieve verification',`${error.name === 'TimeoutError' ? 'The request timed out.' : error.message} No successful result is claimed. You can retry or run the verifier from the repository.`);
  } finally { button.disabled = false; }
}
async function evidence(path) {
  const target = $(`${path}-evidence`);
  try {
    const record = await json(`runs/${path}.json`); target.replaceChildren();
    for (const [step,title] of [['fund','Fund escrow'],['spend',path === 'fill' ? 'Release to solver' : 'Refund to payer']]) {
      const tx = element('div',undefined,'tx');
      tx.append(element('strong',`${title} · Zcash testnet block ${record[`${step}_mined_height`].toLocaleString()}`),element('code',record[`${step}_txid`]));
      tx.append(link('Raw transaction bytes ↓', `runs/${path}.${step}.tx`)); target.append(tx);
    }
    if (path === 'fill') {
      const tx = element('div',undefined,'tx');
      tx.append(element('strong','NEAR testnet · 0.01 wNEAR'),element('code',record.near_tx_hash),link('Open the NEAR transaction ↗',`https://testnet.nearblocks.io/txns/${encodeURIComponent(record.near_tx_hash)}`)); target.append(tx);
    }
    target.append(link('Open the complete run record ↗',`runs/${path}.json`));
  } catch { target.textContent = 'Recorded evidence could not be loaded. Open the repository to inspect runs/.'; }
}
async function start() {
  await Promise.allSettled([evidence('fill'),evidence('refund')]);
  try {
    config = await json('config.json');
    if (!['live','published'].includes(config.mode) || typeof config.report_url !== 'string') throw new Error('Verifier hosting has not been configured.');
    const url = new URL(config.report_url, location.href);
    if (url.protocol !== 'https:' && url.origin !== location.origin) throw new Error('The verifier endpoint must use HTTPS.');
    $('mode-description').textContent = config.mode === 'live'
      ? 'Live verification of recorded testnet runs. Clicking below asks the server to run the same Rust verifier available in the repository.'
      : 'Published verification of recorded testnet runs. GitHub Actions runs the Rust verifier; this page loads its latest timestamped report. Clicking does not start a fresh node query.';
    $('verify-button').textContent = config.mode === 'live' ? 'Verify on testnet →' : 'Load latest verification →';
    $('verify-button').disabled = false; $('verify-button').addEventListener('click',verify);
  } catch(error) {
    $('mode-description').textContent = 'Verification is unavailable.';
    $('verify-button').textContent = 'Verifier unavailable'; setStatus('unavailable','Verifier unavailable',error.message);
  }
}
start();
