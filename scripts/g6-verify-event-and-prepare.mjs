// Candidate-only GitHub Actions transparency anchor preflight.
// No signing key, Owner permit, AWS/Cloudflare token, or GitHub mutation.
// This validates a real previously committed V1 hash-only audit event before
// creating a canonical JSON payload intended for separate Sigstore signing.
import {createHash} from 'node:crypto';
import {writeFile} from 'node:fs/promises';
import {join} from 'node:path';
import {pathToFileURL} from 'node:url';

export class PilotStop extends Error {
  constructor(code) { super(code); this.name='PilotStop'; }
}
const stop=code=>{ throw new PilotStop(code); };
const REP='thaobeoo123/omniroute-witness';
const HEX64=/^[0-9A-F]{64}$/;
const HEX40=/^[0-9a-f]{40}$/;
const DIGEST_DOMAIN='OMNIROUTE_G6_FREE_WITNESS_AUDIT_EVENT_V1';
const HEAD_DOMAIN='OMNIROUTE_G6_FREE_WITNESS_AUDIT_HEAD_V1';
const WITNESS_ID='OMNIROUTE_G6_OWNER_ISSUER_FIRST_USE';
const ANCHOR_DOMAIN='OMNIROUTE_G6_SIGSTORE_HASH_ONLY_ANCHOR_PILOT_V1';
const EVENT_KEYS=[
  'Domain','WitnessId','ScopeSha256','RequestSha256','Revision',
  'PreviousAuditSha256','EventSha256','ExpectedSequence','ProposedSequence'
];

const exact=(o,keys)=>
  o!==null && typeof o==='object' && !Array.isArray(o) &&
  Object.keys(o).length===keys.length && keys.every(k=>Object.hasOwn(o,k));

function canonical(fields) {
  const chunks=[];
  for (const value of fields) {
    if (typeof value!=='string' || !value.length || value.length>512 ||
        value.normalize('NFC')!==value) stop('NONCANONICAL_FIELD');
    const bytes=Buffer.from(value,'utf8');
    const len=Buffer.alloc(4);
    len.writeUInt32BE(bytes.length,0);
    chunks.push(len,bytes);
  }
  return Buffer.concat(chunks);
}
const digest=fields=>createHash('sha256').update(canonical(fields))
  .digest('hex').toUpperCase();

async function getJson(fetcher,url) {
  let response;
  try {
    response=await fetcher(url,{
      method:'GET',redirect:'error',
      headers:{accept:'application/vnd.github+json',
        'user-agent':'OmniRoute-G6-Sigstore-HashOnly-Pilot'}
    });
  } catch { stop('PUBLIC_GITHUB_UNAVAILABLE'); }
  if (response?.status!==200) stop('PUBLIC_GITHUB_UNAVAILABLE');
  try {return await response.json();}
  catch {stop('PUBLIC_GITHUB_MALFORMED_JSON');}
}

function parseInputs(env) {
  if (env.GITHUB_EVENT_NAME!=='workflow_dispatch' ||
      env.GITHUB_REPOSITORY!==REP || env.GITHUB_REF!=='refs/heads/main' ||
      !HEX40.test(env.GITHUB_SHA??'') ||
      !/^\d{1,20}$/.test(env.GITHUB_RUN_ID??'') ||
      !/^\d{1,6}$/.test(env.GITHUB_RUN_ATTEMPT??''))
    stop('WORKFLOW_IDENTITY_INVALID');
  if (![env.G6_INPUT_SCOPE_SHA256,env.G6_INPUT_EVENT_SHA256,
      env.G6_INPUT_AUDIT_HEAD_SHA256].every(s=>HEX64.test(s??'')) ||
      !HEX40.test(env.G6_INPUT_BRANCH_OID??'') ||
      !/^[1-9]\d{0,4}$/.test(env.G6_INPUT_REVISION??''))
    stop('HASH_ONLY_INPUTS_INVALID');
  const rev=Number(env.G6_INPUT_REVISION);
  if (!Number.isSafeInteger(rev)||rev>99999) stop('REVISION_OUT_OF_BOUNDS');
  return rev;
}

function validateEvent(event,env,revision) {
  if (!exact(event,EVENT_KEYS) ||
      event.Domain!==DIGEST_DOMAIN || event.WitnessId!==WITNESS_ID ||
      event.ScopeSha256!==env.G6_INPUT_SCOPE_SHA256 ||
      event.EventSha256!==env.G6_INPUT_EVENT_SHA256 ||
      !HEX64.test(event.RequestSha256??'') ||
      !HEX64.test(event.PreviousAuditSha256??'') ||
      event.Revision!==revision ||
      !Number.isSafeInteger(event.ExpectedSequence) ||
      event.ExpectedSequence<0 || event.ExpectedSequence>1 ||
      event.ProposedSequence!==event.ExpectedSequence+1)
    stop('EVENT_CONTENT_INVALID');
  const computed=digest([DIGEST_DOMAIN,WITNESS_ID,
    event.ScopeSha256,event.RequestSha256,String(event.Revision),
    event.PreviousAuditSha256,String(event.ExpectedSequence),
    String(event.ProposedSequence)]);
  if(computed!==event.EventSha256) stop('EVENT_CANONICAL_SHA_MISMATCH');
  const head=digest([HEAD_DOMAIN,event.PreviousAuditSha256,
    event.EventSha256,String(event.Revision)]);
  if(head!==env.G6_INPUT_AUDIT_HEAD_SHA256) stop('AUDIT_HEAD_SHA_MISMATCH');
  return JSON.stringify(event,Object.keys(event).sort())+'\n';
}

export async function preparePublicAnchor({env,fetcher=globalThis.fetch,writeOutput}={}) {
  if (!env || typeof fetcher!=='function' || typeof writeOutput!=='function')
    stop('PREPARE_DEPENDENCIES_MISSING');
  const revision=parseInputs(env);
  const base='https://api.github.com/repos/'+REP;
  const refUri=base+'/git/ref/heads/witness-audit';
  const head=await getJson(fetcher,refUri);
  if (head?.object?.type!=='commit' ||
      head.object.sha!==env.G6_INPUT_BRANCH_OID)
    stop('AUDITOR_BRANCH_HEAD_NOT_EXACT');
  const eventPath='g6-witness/'+env.G6_INPUT_SCOPE_SHA256.slice(0,16)+
    '/'+String(revision).padStart(6,'0')+'-'+
    env.G6_INPUT_EVENT_SHA256+'.json';
  const file=await getJson(fetcher,base+'/contents/'+eventPath+
    '?ref='+env.G6_INPUT_BRANCH_OID);
  if (file?.type!=='file' || file.path!==eventPath ||
      file.encoding!=='base64' || typeof file.content!=='string')
    stop('AUDIT_FILE_UNVERIFIABLE');
  let raw;
  try {
    const encoded=file.content.replace(/\s/g,'');
    raw=Buffer.from(encoded,'base64').toString('utf8');
    if (Buffer.from(raw,'utf8').toString('base64')!==encoded)
      stop('AUDIT_FILE_BASE64_INVALID');
  } catch {stop('AUDIT_FILE_BASE64_INVALID');}
  let event;
  try {event=JSON.parse(raw);}
  catch {stop('AUDIT_FILE_JSON_INVALID');}
  const canonicalFile=validateEvent(event,env,revision);
  if(raw!==canonicalFile) stop('AUDIT_FILE_NOT_CANONICAL');
  const after=await getJson(fetcher,refUri);
  if(after?.object?.type!=='commit' ||
      after.object.sha!==env.G6_INPUT_BRANCH_OID)
    stop('AUDITOR_BRANCH_MOVED_DURING_PREPARE');
  const payload={
    Domain:ANCHOR_DOMAIN,
    Repository:REP,
    Branch:'witness-audit',
    GitCommitSha:env.G6_INPUT_BRANCH_OID,
    ScopeSha256:event.ScopeSha256,
    EventSha256:event.EventSha256,
    AuditHeadSha256:env.G6_INPUT_AUDIT_HEAD_SHA256,
    Revision:revision,
    WorkflowRef:env.GITHUB_REF,
    WorkflowCommitSha:env.GITHUB_SHA,
    GitHubRunId:env.GITHUB_RUN_ID,
    GitHubRunAttempt:env.GITHUB_RUN_ATTEMPT
  };
  // All fields are public identifiers/hash-only. Never emit an auth token.
  await writeOutput(JSON.stringify(payload,Object.keys(payload).sort())+'\n');
  return Object.freeze({
    status:'HASH_ONLY_ANCHOR_PAYLOAD_PREPARED_NOT_SIGNED',
    repository:REP,gitCommitSha:env.G6_INPUT_BRANCH_OID,
    eventSha256:event.EventSha256,
    signerIdentityVerified:false,
    sigstoreInclusionVerified:false,
    auditorP256PinProven:false,
    ownerGate:'NOT_ISSUED'
  });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    if(!process.env.RUNNER_TEMP || !process.env.GITHUB_ACTIONS ||
       process.env.GITHUB_ACTIONS!=='true') stop('GITHUB_RUNNER_CONTEXT_REQUIRED');
    const dest=join(process.env.RUNNER_TEMP,'g6-audit-anchor-pilot.json');
    const result=await preparePublicAnchor({
      env:process.env,
      writeOutput:content=>writeFile(dest,content,{flag:'wx',mode:0o600})
    });
    console.log(result.status);
  } catch(e) {
    console.error('G6_AUDIT_ANCHOR_PILOT_BLOCKED='+
      (e?.name==='PilotStop'?e.message:'UNEXPECTED_FAILURE'));
    process.exitCode=2;
  }
}

