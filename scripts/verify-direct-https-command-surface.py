#!/usr/bin/env python3
import json, ssl, time, urllib.parse, urllib.request, argparse
from pathlib import Path
from datetime import datetime, timezone

def iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec='seconds')

class Api:
    def __init__(self, base):
        self.base=base.rstrip('/')
        self.ctx=ssl._create_unverified_context()
        self.token=None
    def req(self,path,method='GET',data=None,timeout=25):
        headers={}
        body=None
        if self.token: headers['Authorization']='Bearer '+self.token
        if data is not None:
            headers['Content-Type']='application/json'; body=json.dumps(data).encode()
        r=urllib.request.Request(self.base+path,data=body,headers=headers,method=method)
        with urllib.request.urlopen(r,context=self.ctx,timeout=timeout) as resp:
            raw=resp.read().decode('utf-8','replace')
            try: return json.loads(raw)
            except Exception: return {'_raw':raw,'_status':resp.status}
    def login(self):
        obj=self.req('/login','POST',{'username':'ctf','password':'CHANGE_ME_PASSWORD','version':'surface-verify'})
        self.token=obj['access_token']
    def raw(self,aid,cmdline):
        return self.req('/agent/command/raw','POST',{'id':aid,'cmdline':cmdline})
    def tasks(self,aid,limit=80):
        qs=urllib.parse.urlencode({'agent_id':aid,'limit':limit})
        return self.req('/agent/task/list?'+qs)

def wait_task(api, aid, cmdline, start, timeout):
    end=time.time()+timeout
    while time.time()<end:
        tasks=api.tasks(aid)
        if isinstance(tasks,list):
            matches=[t for t in tasks if t.get('a_cmdline')==cmdline and t.get('a_completed') and int(t.get('a_start_time') or 0)>=start]
            if matches:
                matches.sort(key=lambda t:int(t.get('a_start_time') or 0), reverse=True)
                return matches[0]
        time.sleep(1)
    return None

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--base',default='https://127.0.0.1:4321/endpoint')
    ap.add_argument('--timeout',type=int,default=25)
    ap.add_argument('--report',default='')
    ns=ap.parse_args()
    api=Api(ns.base); api.login()
    agents=api.req('/agent/list')
    direct=sorted([a for a in agents if a.get('a_name')=='direct_https'], key=lambda a:int(a.get('a_last_tick') or 0), reverse=True)
    if not direct: raise SystemExit('no direct_https agent')
    agent=direct[0]; aid=agent['a_id']
    out={'started_at':iso(),'agent':agent,'checks':[]}
    reject=['disks','exfil stop 12345678']
    allow=['hello','cmd echo POST_CUT_CMD','powershell Write-Output POST_CUT_PS','pwd']
    for cmd in reject:
        resp=api.raw(aid,cmd)
        out['checks'].append({'cmdline':cmd,'expected':'rejected','response':resp,'passed':resp.get('ok') is False})
    for cmd in allow:
        start=int(time.time())
        resp=api.raw(aid,cmd)
        task=wait_task(api,aid,cmd,start,ns.timeout) if resp.get('ok') else None
        out['checks'].append({'cmdline':cmd,'expected':'completed','response':resp,'task':task,'passed':bool(resp.get('ok') and task)})
    out['finished_at']=iso()
    text=json.dumps(out,ensure_ascii=False,indent=2)
    if ns.report:
        Path(ns.report).parent.mkdir(parents=True,exist_ok=True)
        Path(ns.report).write_text(text+'\n',encoding='utf-8')
    print(text)
    if not all(c['passed'] for c in out['checks']):
        raise SystemExit(1)
if __name__=='__main__': main()
