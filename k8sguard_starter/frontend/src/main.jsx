import React, {useState} from 'react';
import {createRoot} from 'react-dom/client';
import './style.scss';
const API = 'http://127.0.0.1:8000';
function App(){
 const [page,setPage]=useState('Overview'),[result,setResult]=useState(null),[error,setError]=useState(''),[loading,setLoading]=useState(false);
 const pages=['Overview','Scans','Attack Graph','Findings','Cross-Namespace','Runtime Monitoring','Policy Generation'];
 async function onFile(e){const f=e.target.files?.[0];if(!f)return;setError('');setLoading(true);const fd=new FormData();fd.append('file',f);
 try{let r=await fetch(`${API}/api/scans/manifests`,{method:'POST',body:fd});let d=await r.json();if(!r.ok)throw Error(d.detail||'Scan failed');setResult(d);setPage('Overview');}catch(ex){setError(ex.message)}finally{setLoading(false)}}
 const findings=result?.findings||[];
 return <div className="shell"><aside><div className="logo">⬡ K8sGuard</div><div className="hint">Kubernetes security console</div><nav>{pages.map(p=><button className={page===p?'active':''} key={p} onClick={()=>setPage(p)}>{p}{p.includes('Monitoring')||p.includes('Generation')?<small>Future</small>:null}</button>)}</nav><div className="foot">FYP-1 • Module A</div></aside><main><header><div><div className="eyebrow">STATIC SECURITY ANALYSIS</div><h1>{page}</h1></div><label className="upload">{loading?'Scanning…':'Upload YAML'}<input type="file" accept=".yaml,.yml,.json" onChange={onFile} disabled={loading}/></label></header>{error&&<div className="error">{error}</div>}
 {(page==='Runtime Monitoring'||page==='Policy Generation')?<div className="panel"><h2>Planned module</h2><p>This module is not implemented in the FYP-1 mid-evaluation prototype. No runtime or policy-generation data is available.</p></div>:
 !result?<div className="panel empty"><h2>No scan loaded</h2><p>Upload <code>fixtures/insecure.yaml</code> from the project folder to see real computed Module A results.</p></div>:
 page==='Overview'||page==='Scans'?<><div className="metrics"><div><small>Resources</small><strong>{result.resources}</strong></div><div><small>Graph nodes</small><strong>{result.nodes.length}</strong></div><div><small>Relationships</small><strong>{result.edges.length}</strong></div><div><small>Findings</small><strong>{findings.length}</strong></div></div><div className="panel"><h2>Latest scan</h2><p>Scan ID: {result.scan_id}</p><p>All counts are computed from uploaded manifests.</p><button onClick={()=>{const blob=new Blob([JSON.stringify(result,null,2)],{type:'application/json'});const a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='k8sguard-scan.json';a.click();URL.revokeObjectURL(a.href)}}>Export JSON</button></div></>:
 page==='Findings'?<div className="panel"><h2>Detected capabilities and risks</h2>{findings.length?findings.map(f=><div className="finding" key={f.id}><span className={'severity '+f.severity}>{f.severity}</span><strong>{f.rule}</strong><p>{f.description}</p><small>{f.resource}</small></div>):'No supported rules triggered.'}</div>:
 page==='Attack Graph'?<div className="panel"><h2>Typed graph (edge list)</h2><p>Interactive path visualization comes in the next stage. These edges come from the backend analysis.</p>{result.edges.map((e,i)=><div className="edge" key={i}><code>{e.source}</code><span>→ {e.relation} →</span><code>{e.target}</code></div>)}</div>:
 <div className="panel"><h2>Cross-namespace analysis</h2><p>Operator and CRD reference detection will be implemented in the next Module A stage. No results are claimed yet.</p></div>}
 </main></div>
}
createRoot(document.getElementById('root')).render(<App/>);
