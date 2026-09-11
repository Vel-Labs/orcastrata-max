import contextlib, io, json, os, subprocess, tempfile, threading, time, unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest.mock import patch
import sys
sys.path.insert(0, str(Path(__file__).parents[1] / 'scripts'))
import local_qwopus_loop as loop

REAL_ROOT=loop.ROOT
RUN=REAL_ROOT/loop.RUN_REL
BASE=subprocess.check_output(['git','rev-parse','HEAD'],cwd=REAL_ROOT,text=True).strip()
MODEL='Jackrong/Qwopus3.8-27B-Flash-GGUF'

class SseServer:
    def __init__(self, mode='good'):
        self.mode=mode; self.calls=0; self.last_body=None
        owner=self
        class H(BaseHTTPRequestHandler):
            def do_POST(self):
                owner.calls += 1
                n=int(self.headers.get('Content-Length','0')); body=json.loads(self.rfile.read(n)); owner.last_body=body; msg=body['messages'][0]['content']
                start=msg.find('{"identity"'); identity=json.JSONDecoder().raw_decode(msg[start:])[0]['identity']
                if owner.mode=='redirect':
                    self.send_response(302); self.send_header('Location','http://127.0.0.1:1/v1/chat/completions'); self.end_headers(); return
                if owner.mode=='slow':
                    self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.end_headers(); self.wfile.write(b'data: {"model":"'+MODEL.encode()+b'","choices":[{"delta":{"content":"{"}}]}\n\n'); self.wfile.flush(); time.sleep(1)
                    return
                bad=owner.mode=='malformed' or (owner.mode=='repair' and owner.calls==1)
                if bad: content='{"bad":'; reason='length'
                else:
                    candidate={'task_id':identity['task_id'],'model':identity['model'],'input_sha256':identity['input_sha256'],'status':'candidate_ready','findings':[{'path':identity['paths'][0],'finding':'bounded Qwopus candidate'}]}
                    content=json.dumps(candidate); reason='stop'
                self.send_response(200); self.send_header('Content-Type','text/event-stream'); self.end_headers()
                if owner.mode == 'event_overflow':
                    payload = {'model': MODEL, 'choices': [{'delta': {'reasoning_content': 'x' * (loop.MAX_EVENT_BYTES + 1024)}}]}
                    self.wfile.write(('data: ' + json.dumps(payload) + '\n\n').encode()); self.wfile.flush(); return
                if owner.mode == 'content_overflow':
                    for _ in range(3):
                        payload = {'model': MODEL, 'choices': [{'delta': {'content': 'c' * 800000}}]}
                        self.wfile.write(('data: ' + json.dumps(payload) + '\n\n').encode()); self.wfile.flush()
                    return
                if owner.mode == 'overhead':
                    candidate = {'task_id': identity['task_id'], 'model': identity['model'], 'input_sha256': identity['input_sha256'], 'status': 'candidate_ready', 'findings': [{'path': identity['paths'][0], 'finding': 'bounded Qwopus candidate'}]}
                    for _ in range(3):
                        payload = {'model': MODEL, 'choices': [{'delta': {'reasoning_content': 'r' * 900000}}]}
                        self.wfile.write(('data: ' + json.dumps(payload) + '\n\n').encode()); self.wfile.flush()
                    payload = {'model': MODEL, 'choices': [{'delta': {'content': json.dumps(candidate)}, 'finish_reason': None}]}
                    self.wfile.write(('data: ' + json.dumps(payload) + '\n\n').encode())
                    self.wfile.write(('data: ' + json.dumps({'model': MODEL, 'choices': [{'delta': {}, 'finish_reason': 'stop'}]}) + '\n\ndata: [DONE]\n\n').encode()); self.wfile.flush(); return
                if owner.mode == 'eof':
                    chunk={'model':MODEL,'choices':[{'delta':{'content':content},'finish_reason':None}]}
                    self.wfile.write(('data: '+json.dumps(chunk)+'\n\n').encode()); self.wfile.flush(); return
                parts = [content] if owner.mode != 'progress' else [content[i:i+30] for i in range(0,len(content),30)]
                for part in parts:
                    chunk={'model':MODEL,'choices':[{'delta':{'content':part},'finish_reason':None}]}; self.wfile.write(('data: '+json.dumps(chunk)+'\n\n').encode()); self.wfile.flush()
                    if owner.mode == 'progress': time.sleep(0.02)
                final={'model':MODEL,'choices':[{'delta':{},'finish_reason':reason}]}; self.wfile.write(('data: '+json.dumps(final)+'\n\ndata: [DONE]\n\n').encode()); self.wfile.flush()
            def log_message(self,*a): pass
        self.http=HTTPServer(('127.0.0.1',0),H); self.thread=threading.Thread(target=self.http.serve_forever,daemon=True); self.thread.start()
    @property
    def endpoint(self): return f'http://127.0.0.1:{self.http.server_port}/v1/chat/completions'
    def close(self): self.http.shutdown(); self.thread.join(timeout=2); self.http.server_close()

class LoopTests(unittest.TestCase):
    def setUp(self):
        self.original_root=loop.ROOT
        self.container=Path(tempfile.mkdtemp(prefix='test-',dir=RUN)); self.tmp=self.container/'fake-root'; self.tmp.mkdir(); loop.ROOT=self.tmp; runroot=self.tmp/loop.RUN_REL; runroot.mkdir(parents=True,exist_ok=True)
        self.git_patch=patch('local_qwopus_loop.subprocess.check_output',return_value=BASE+'\n'); self.git_patch.start()
        for name in ('scripts/local_qwopus_loop.py','tests/test_local_qwopus_loop.py'):
            dest=self.tmp/name; dest.parent.mkdir(exist_ok=True); dest.write_bytes((REAL_ROOT/name).read_bytes())
        self.task=runroot/'task.txt'; self.task.write_text('Describe this bounded input.'); self.src=runroot/'source.txt'; self.src.write_text('known fact'); self.files=runroot/'files.json'; self.files.write_text(json.dumps([str(self.src.relative_to(loop.ROOT))])); self.out=runroot/'out'
    def tearDown(self):
        self.git_patch.stop(); loop.ROOT=self.original_root
        import shutil; shutil.rmtree(self.container,ignore_errors=True)
    def args(self,server,task_id='TEST-LOOP',watchdog=300):
        return type('A',(),dict(task_id=task_id,task=str(self.task.relative_to(loop.ROOT)),worktree=str(loop.ROOT),base=BASE,model=MODEL,endpoint=server.endpoint,files=str(self.files.relative_to(loop.ROOT)),output=str(self.out),watchdog=watchdog))()
    def test_request_body_requires_json_object_response_format(self):
        s=SseServer(); a=self.args(s,task_id='JSON-FORMAT'); loop.run(a)
        self.assertEqual(s.last_body['response_format']['type'], 'json_schema')
        self.assertEqual(s.last_body['response_format']['json_schema']['schema']['required'], ['task_id', 'model', 'input_sha256', 'status', 'findings'])
        self.assertTrue(s.last_body['stream'])
        self.assertFalse(s.last_body['enable_tools'])
        s.close()

    def test_studio_routing_preserves_resume_and_other_endpoints(self):
        legacy = 'http://127.0.0.1:63604/v1/chat/completions'
        studio = 'http://127.0.0.1:8888/v1/chat/completions'
        for endpoint, resume, expected in ((legacy, False, studio), (legacy, True, legacy), (studio, False, studio)):
            server = type('Server', (), {'endpoint': endpoint})()
            args = self.args(server)
            with patch('local_qwopus_loop.run_locked', side_effect=lambda a, *rest: a.endpoint):
                self.assertEqual(loop.run(args, resume), expected)

    def test_validate_state_exact_schema_and_errors(self):
        good={'schema_version':1,'binding':{},'attempt':0,'errors':[],'status':'running'}
        self.assertEqual(loop.validate_state(good),good)
        for bad in ({'binding':{},'attempt':0,'errors':[],'status':'running'}, {**good,'schema_version':2}, {**good,'errors':['bad']}, {**good,'extra':1}):
            with self.assertRaises(loop.LoopError): loop.validate_state(bad)

    def test_findings_must_cover_each_source(self):
        s=SseServer(); a=self.args(s,task_id='FINDINGS'); packet,bind=loop.inputs(a,loop.ROOT)
        candidate={'task_id':bind['task_id'],'model':MODEL,'input_sha256':bind['input_sha256'],'status':'candidate_ready','findings':[]}
        with self.assertRaises(loop.LoopError): loop.validate_candidate(candidate,bind)
        candidate['findings']=[{'path':bind['paths'][0],'finding':'valid one-file answer'}]
        bind['paths'].append('second-source.txt')
        with self.assertRaisesRegex(loop.LoopError,'findings_incomplete'): loop.validate_candidate(candidate,bind)
        s.close()

    def test_wrong_identity_and_source_change(self):
        s=SseServer(); a=self.args(s,task_id='IDENTITY'); candidate=loop.run(a)
        _,bind=loop.inputs(a,loop.ROOT)
        for key in ('task_id','model','input_sha256'):
            with self.assertRaises(loop.LoopError):loop.validate_candidate({**candidate,key:'wrong'},bind)
        checkpoint=(self.out/'IDENTITY.checkpoint.json').read_bytes()
        self.src.write_text('changed source')
        with self.assertRaises(loop.LoopError):loop.run(a,True)
        self.assertEqual((self.out/'IDENTITY.checkpoint.json').read_bytes(),checkpoint)
        s.close()

    def test_stream_transport_allows_reasoning_overhead_above_content_limit(self):
        self.assertEqual(loop.MAX_STREAM_BYTES, 16 * 1024 * 1024)
        self.assertEqual(loop.MAX_EVENT_BYTES, loop.MAX_BYTES)
        s=SseServer('overhead'); a=self.args(s,task_id='STREAM-OVERHEAD'); packet,bind=loop.inputs(a,loop.ROOT)
        raw=loop.call(s.endpoint,MODEL,loop.make_prompt(packet,bind,[]),0.05,lambda event: None)
        self.assertEqual(loop.parse_response(raw,bind)['status'],'candidate_ready')
        self.assertGreater(loop.LAST_CALL_METADATA['bytes_received'], loop.MAX_BYTES)
        self.assertLess(loop.LAST_CALL_METADATA['bytes_received'], loop.MAX_STREAM_BYTES)
        s.close()

    def test_stream_event_limit_rejects_one_oversized_event(self):
        s=SseServer('event_overflow'); a=self.args(s,task_id='STREAM-EVENT')
        with self.assertRaises(loop.LoopError):
            loop.run(a)
        errors=json.loads((self.out/'STREAM-EVENT.escalation.json').read_text())['errors']
        self.assertTrue(any(e['code']=='response_event_too_large' for e in errors))
        s.close()

    def test_stream_content_limit_rejects_cumulative_content_overflow(self):
        s=SseServer('content_overflow'); a=self.args(s,task_id='STREAM-CONTENT')
        with self.assertRaises(loop.LoopError):
            loop.run(a)
        errors=json.loads((self.out/'STREAM-CONTENT.escalation.json').read_text())['errors']
        self.assertTrue(any(e['code']=='response_content_too_large' for e in errors))
        s.close()

    def test_progress_continues_past_multiple_watchdog_intervals(self):
        self.assertEqual(loop.DEFAULT_WATCHDOG,300)
        s=SseServer('progress'); a=self.args(s,task_id='PROGRESS'); packet,bind=loop.inputs(a,loop.ROOT); events=[]
        raw=loop.call(s.endpoint,MODEL,loop.make_prompt(packet,bind,[]),0.05,events.append)
        self.assertEqual(loop.parse_response(raw,bind)['status'],'candidate_ready')
        self.assertGreaterEqual(len(events),2)
        self.assertTrue(any(e['status']=='progressing' for e in events)); s.close()

    def test_persistent_provider_lease_blocks_other_tasks(self):
        s=SseServer(); lease=loop.ROOT/loop.RUN_REL/'provider-lease.json'
        loop.atomic_json(lease,{'status':'inflight','task_id':'UNKNOWN','endpoint':s.endpoint,'pid':0})
        try:
            for task_id in ('LEASE-A','LEASE-B'):
                with self.assertRaises(loop.LoopError): loop.run(self.args(s,task_id=task_id))
                cp=json.loads((self.out/f'{task_id}.checkpoint.json').read_text())
                self.assertTrue(any(e['code']=='provider_outcome_unknown' for e in cp['errors']))
        finally:
            loop.atomic_json(lease,{'status':'released','task_id':'test','endpoint':s.endpoint,'pid':0}); s.close()

    def test_live_shape_capture_and_fresh_resume(self):
        s=SseServer(); a=self.args(s); got=loop.run(a); self.assertEqual(got['status'],'candidate_ready'); calls=s.calls; self.assertEqual(loop.run(a,True),got); self.assertEqual(s.calls,calls); s.close()
    def test_malformed_final_uses_changed_repair(self):
        s=SseServer('repair'); got=loop.run(self.args(s,task_id='REPAIR')); self.assertEqual(got['status'],'candidate_ready'); self.assertEqual(s.calls,2)
        first=json.loads((self.out/'REPAIR.attempt-1.transport.json').read_text()); second=json.loads((self.out/'REPAIR.attempt-2.transport.json').read_text())
        self.assertTrue(first['done_observed']); self.assertEqual(first['finish_reason'],'length'); self.assertTrue(second['done_observed']); self.assertEqual(second['finish_reason'],'stop'); s.close()
    def test_eof_metadata_distinguishes_missing_done(self):
        s=SseServer('eof'); a=self.args(s,task_id='EOF-META')
        with self.assertRaises(loop.LoopError): loop.run(a)
        meta=json.loads((self.out/'EOF-META.attempt-1.transport.json').read_text())
        self.assertFalse(meta['done_observed']); self.assertIsNone(meta['finish_reason']); self.assertEqual(meta['requested_model'],MODEL); self.assertGreater(meta['bytes_received'],0); s.close()

    def test_identity_and_schema_failures_escalate(self):
        s=SseServer('malformed'); self.assertRaises(loop.LoopError,loop.run,self.args(s)); cp=json.loads((self.out/'TEST-LOOP.checkpoint.json').read_text()); self.assertEqual(cp['status'],'escalated'); self.assertTrue((self.out/'TEST-LOOP.escalation.json').exists()); s.close()
    def test_stale_resume_and_source_drift(self):
        s=SseServer(); a=self.args(s); loop.run(a); self.task.write_text('changed'); self.assertRaises(loop.LoopError,loop.run,a,True); s.close()
    def test_input_symlink_and_parent_symlink_rejected(self):
        link=self.tmp/'link'; link.symlink_to(self.src)
        with self.assertRaises(loop.LoopError):
            loop.safe_regular(str(link.relative_to(loop.ROOT)),loop.ROOT)
        parent=self.tmp/'parent'; parent.mkdir(); (parent/'x').write_text('x'); p=self.tmp/'parent-link'; p.symlink_to(parent, target_is_directory=True)
        with self.assertRaises(loop.LoopError):
            loop.safe_regular(str((p/'x').relative_to(loop.ROOT)),loop.ROOT)
    def test_endpoint_redirect_and_output_boundary(self):
        with self.assertRaises(loop.LoopError): loop.endpoint_url('http://127.0.0.1:1@evil:2/v1/chat/completions')
        with self.assertRaises(loop.LoopError): loop.output_dir(loop.ROOT/'docs',loop.ROOT)
        s=SseServer('redirect')
        with self.assertRaises(loop.LoopError): loop.run(self.args(s,task_id='REDIRECT'))
        s.close()

    def test_watchdog_progress_callback_uses_stall_signal(self):
        s=SseServer('slow'); a=self.args(s,task_id='WATCHDOG'); packet,bind=loop.inputs(a,loop.ROOT); events=[]
        with self.assertRaises(loop.LoopError): loop.call(s.endpoint,MODEL,loop.make_prompt(packet,bind,[]),0.05,events.append)
        self.assertTrue(any(e.get('status')=='stall_suspected' for e in events)); s.close()
    def test_interrupted_request_escalates_without_duplicate(self):
        s=SseServer(); a=self.args(s,task_id='INTERRUPTED')
        with patch.object(loop,'call',side_effect=loop.LoopError('watchdog_stalled')): self.assertRaises(loop.LoopError,loop.run,a)
        cp=json.loads((self.out/'INTERRUPTED.checkpoint.json').read_text()); self.assertEqual(cp['status'],'escalated'); self.assertEqual(s.calls,0); s.close()
    def test_repairing_resume_preserves_errors(self):
        s=SseServer(); a=self.args(s,task_id='REPAIRING'); packet,bind=loop.inputs(a,loop.ROOT); self.out.mkdir(); loop.atomic_json(self.out/'REPAIRING.checkpoint.json',{'schema_version':1,'binding':bind,'attempt':1,'errors':[{'code':'response_incomplete','detail':'simulated'}],'status':'repairing'})
        with patch.object(loop,'call',side_effect=loop.LoopError('watchdog_stalled')): self.assertRaises(loop.LoopError,loop.run,a,True)
        cp=json.loads((self.out/'REPAIRING.checkpoint.json').read_text()); self.assertTrue(any(e.get('code')=='response_incomplete' for e in cp['errors'])); self.assertTrue(any(e.get('code')=='watchdog_stalled' for e in cp['errors'])); s.close()

    def c0_packet(self):
        target=self.tmp/'bootstrap-target.txt'; target.write_text('before\n')
        import importlib.util
        spec=importlib.util.spec_from_file_location('c0_patcher_test',REAL_ROOT/'plugins/codexmax-orchestrator/scripts/provider_patch_application.py')
        mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
        write={'path':'bootstrap-target.txt','before_sha256':mod.sha256(target.read_bytes()),'max_bytes':4096}
        return ({'run_id':'C0-TEST-RUN','chunk_id':'C0','packet_id':'C0-TEST-PACKET','attempt':1,
                 'worktree':str(self.tmp),'base':BASE,'model':MODEL,'objective':'apply one bounded fixture edit',
                 'inputs':[{'path':'docs/qwopus-loop/run/task.txt','sha256':loop.digest(self.task.read_bytes())}],
                 'writes':[write],'exclusions':['protected release','product payload'],'validation':[[sys.executable,'-c',"from pathlib import Path; assert Path('bootstrap-target.txt').read_text() == 'after\\n'"]],
                 'oracle':'fixture contains repaired text','failure_history':[],'successor':'C1'},
                mod, target)

    def c0_applied(self):
        packet, mod, target=self.c0_packet()
        queue_path=self.tmp/loop.RUN_REL/'queue.json'
        encoded={'patch':'--- a/bootstrap-target.txt\n+++ b/bootstrap-target.txt\n@@ -1 +1 @@\n-before\n+after\n',
                 'rationale':'bounded fixture change','tests':packet['validation'],'unresolved':[]}
        candidate={'task_id':packet['run_id'],'model':packet['model'],'status':'candidate_ready',
                   'findings':[{'path':'bootstrap-target.txt','finding':json.dumps(encoded)}]}
        proposal=loop.proposal_from_c0_candidate(candidate,packet)
        applied=loop.apply_c0_proposal_recorded(queue_path=queue_path,packet=packet,proposal=proposal,root=self.tmp)
        loop.validate_c0_applied(queue_path,packet,self.tmp)
        review={'reviewer_session':'/root/delegation_gap','recorded_by':'/root',
                'candidate_sha256':applied['candidate_sha256'],'decision':'accept',
                'source_sha256':loop.c0_source_hashes(packet,self.tmp),'findings':[],
                'proof_boundary':'synthetic reviewer for controller regression only'}
        path=self.tmp/loop.RUN_REL/'c0-independent-review.json'
        loop.atomic_json(path,review)
        return packet,queue_path,self.tmp/loop.RUN_REL/'checkpoint.json',loop.digest(path.read_bytes())

    def test_c0_executed_validation_review_and_recoverable_commit(self):
        packet,q,cp,review_hash=self.c0_applied()
        original=loop.atomic_json
        def interrupt_projection(path,value):
            if path==cp: raise OSError('simulated interruption after queue commit')
            original(path,value)
        with patch.object(loop,'atomic_json',side_effect=interrupt_projection):
            with self.assertRaises(OSError):
                loop.advance_c0_checkpoint(queue_path=q,checkpoint_path=cp,packet=packet,review_sha256=review_hash)
        self.assertFalse(cp.exists())
        accepted=json.loads(q.read_text())['checkpoint']
        got=loop.advance_c0_checkpoint(queue_path=q,checkpoint_path=cp,packet=packet,review_sha256=review_hash)
        self.assertEqual(got,accepted); self.assertEqual(json.loads(cp.read_text()),accepted)
        self.assertEqual(got['tests'][0]['returncode'],0)

    def test_c0_invalid_queue_or_stale_review_never_writes_checkpoint(self):
        packet,q,cp,review_hash=self.c0_applied(); before=q.read_bytes()
        review=self.tmp/loop.RUN_REL/'c0-independent-review.json'
        review.write_text(review.read_text()+' ')
        with self.assertRaisesRegex(loop.LoopError,'c0_review_digest'):
            loop.advance_c0_checkpoint(queue_path=q,checkpoint_path=cp,packet=packet,review_sha256=review_hash)
        self.assertFalse(cp.exists()); self.assertEqual(q.read_bytes(),before)
        q.write_text('{}')
        with self.assertRaisesRegex(loop.LoopError,'c0_queue_binding'):
            loop.advance_c0_checkpoint(queue_path=q,checkpoint_path=cp,packet=packet,review_sha256=review_hash)
        self.assertFalse(cp.exists())

    def test_c0_validation_and_review_reject_current_source_drift(self):
        packet,q,cp,review_hash=self.c0_applied()
        self.task.write_text('different input')
        with self.assertRaises(loop.LoopError):
            loop.advance_c0_checkpoint(queue_path=q,checkpoint_path=cp,packet=packet,review_sha256=review_hash)
        self.assertFalse(cp.exists())

    def test_artifact_cli_run_and_resume_in_fresh_processes(self):
        server=SseServer()
        args=self.args(server,task_id='CLI-ROUNDTRIP')
        argv=[sys.executable,str(self.tmp/'scripts/local_qwopus_loop.py'),'run']
        for name in ('task_id','task','worktree','base','model','endpoint','files','output'):
            argv.extend(['--'+name.replace('_','-'),str(getattr(args,name))])
        try:
            first=subprocess.run(argv,cwd=self.tmp,capture_output=True,text=True)
            self.assertEqual(first.returncode,0,first.stderr)
            argv[2]='resume'
            resumed=subprocess.run(argv,cwd=self.tmp,capture_output=True,text=True)
            self.assertEqual(resumed.returncode,0,resumed.stderr)
            self.assertEqual(json.loads(first.stdout),json.loads(resumed.stdout))
            self.assertEqual(server.calls,1)
        finally:
            server.close()

    def test_c0_cli_lock_is_shared_in_real_subprocess(self):
        argv=[sys.executable,str(self.tmp/'scripts/local_qwopus_loop.py'),'c0-apply',
              '--worktree',str(self.tmp),'--packet','unused','--proposal','unused','--queue','unused']
        with loop.c0_locked(self.tmp):
            got=subprocess.run(argv,cwd=self.tmp,capture_output=True,text=True)
        self.assertEqual(got.returncode,2); self.assertIn('runner_already_active',got.stderr)

    def test_c0_restart_reconciles_unknown_apply_without_replay(self):
        packet, mod, target=self.c0_packet(); queue_path=self.tmp/loop.RUN_REL/'queue.json'
        before={ 'bootstrap-target.txt': mod.sha256(target.read_bytes()) }; after={'bootstrap-target.txt':mod.sha256(b'after\n')}
        loop.atomic_json(queue_path,{'schema_version':1,'run_id':'C0-TEST-RUN','packets':[],'active_chunk':'C0','pending_apply':{'status':'apply_pending','candidate_sha256':'candidate-c0','packet_sha256':loop.digest(loop.canonical(packet).encode()),'before_hashes':before,'after_hashes':after}})
        target.write_text('different\n')
        with self.assertRaisesRegex(loop.LoopError,'c0_apply_outcome_unknown'): loop.reconcile_c0_pending(queue_path=queue_path,packet=packet,root=self.tmp)
        target.write_text('after\n')
        with self.assertRaisesRegex(loop.LoopError,'c0_apply_already_applied'): loop.reconcile_c0_pending(queue_path=queue_path,packet=packet,root=self.tmp)

    def test_c0_provider_artifact_becomes_controller_hashed_proposal(self):
        packet, mod, target=self.c0_packet()
        encoded={'patch':'--- a/bootstrap-target.txt\n+++ b/bootstrap-target.txt\n@@ -1 +1 @@\n-before\n+after\n',
                 'rationale':'Qwopus bounded proposal','tests':[['python3','-m','unittest','-q']],'unresolved':[]}
        candidate={'task_id':packet['run_id'],'model':packet['model'],'status':'candidate_ready',
                   'findings':[{'path':'bootstrap-target.txt','finding':json.dumps(encoded)}]}
        proposal=loop.proposal_from_c0_candidate(candidate,packet)
        self.assertEqual(proposal['candidate_sha256'],loop.digest(loop.canonical({'packet_id':packet['packet_id'],**encoded}).encode()))
        self.assertNotIn('candidate_sha256',encoded)

    def test_c0_cli_rejects_fake_root_before_any_write(self):
        packet, mod, target=self.c0_packet(); encoded={'patch':'--- a/bootstrap-target.txt\n+++ b/bootstrap-target.txt\n@@ -1 +1 @@\n-before\n+after\n','rationale':'cli proposal','tests':[['grep','-q','^after$','bootstrap-target.txt']],'unresolved':[]}
        proposal={**encoded,'run_id':packet['run_id'],'chunk_id':packet['chunk_id'],'packet_id':packet['packet_id'],'attempt':packet['attempt'],'candidate_sha256':'controller-derives'}
        packet_path=self.tmp/loop.RUN_REL/'packet.json'; proposal_path=self.tmp/loop.RUN_REL/'proposal.json'; queue_path=self.tmp/loop.RUN_REL/'queue.json'
        packet_path.write_text(json.dumps(packet)); proposal_path.write_text(json.dumps(proposal))
        output=io.StringIO()
        with patch.object(loop, 'ROOT', REAL_ROOT), contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(loop.main(['c0-apply','--packet',str(packet_path),'--proposal',str(proposal_path),'--worktree',str(self.tmp),'--queue',str(queue_path)]),2)
        self.assertEqual(target.read_text(),'before\n'); self.assertIn('wrong_worktree',output.getvalue())

    def test_c0_reviewer_loader_rejects_non_parent_provenance(self):
        path=self.tmp/loop.RUN_REL/'review.json'; value={'reviewer_session':'/root/other','recorded_by':'/root','decision':'accept','candidate_sha256':'x','source_sha256':{},'findings':[],'proof_boundary':'independent'}; path.write_text(json.dumps(value))
        with self.assertRaisesRegex(loop.LoopError,'c0_review_provenance'):
            loop.load_c0_reviewer(path,candidate_sha256='x',expected_sha256=loop.digest(path.read_bytes()),source_hashes={})

if __name__=='__main__': unittest.main()
