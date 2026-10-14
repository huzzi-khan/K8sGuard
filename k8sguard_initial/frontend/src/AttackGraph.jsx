import React,{useMemo,useRef,useState,useEffect} from 'react';
import './attack-graph.scss';
const kind=n=>String(n.kind||n.type||n.id?.split('/')[0]||'Resource');
const label=n=>String(n.label||n.name||n.id?.split('/').pop()||n.id);
const ns=n=>n.namespace||String(n.id||'').split('/')[1]||'cluster';
const groups={ServiceAccount:['circle','#DCE7FD','#326CE5',14],Role:['rect','#E4ECFB','#2557C4',13],ClusterRole:['rect','#E4ECFB','#2557C4',13],RoleBinding:['diamond','#F1F5FC','#7B93B8',9],ClusterRoleBinding:['diamond','#F1F5FC','#7B93B8',9],Secret:['rect','#FBF3E3','#A9701C',12],NetworkPolicy:['hex','#E7DEFB','#6D4AC9',13],Pod:['circle','#DCE7FD','#326CE5',14],Deployment:['circle','#DCE7FD','#326CE5',14],CustomResourceDefinition:['hex','#DFF1F1','#0E6E70',15],ClusterIssuer:['hex','#FBE3EC','#9F1239',15]};
const cfg=n=>groups[kind(n)]|| (['Namespace','Node'].includes(kind(n))?['hex','#FBE3EC','#9F1239',14]:['rect','#EFF3F8','#66788F',12]);
function Shape({node:n,x,y,chosen}){const [shape,fill,stroke,r]=cfg(n);const extra=chosen?<circle cx={x} cy={y} r={r+8} stroke="#326CE5" strokeWidth="2" fill="none"/>:null;let el;if(shape==='circle')el=<circle cx={x} cy={y} r={r} fill={fill} stroke={stroke} strokeWidth="2"/>;else if(shape==='diamond')el=<rect x={x-r} y={y-r} width={r*2} height={r*2} transform={`rotate(45 ${x} ${y})`} rx="2" fill={fill} stroke={stroke} strokeWidth="1.8"/>;else if(shape==='hex'){const points=Array.from({length:6},(_,i)=>`${x+r*Math.cos((i*60-90)*Math.PI/180)},${y+r*Math.sin((i*60-90)*Math.PI/180)}`).join(' ');el=<polygon points={points} fill={fill} stroke={stroke} strokeWidth="2"/>}else el=<rect x={x-r} y={y-r*.77} width={r*2} height={r*1.54} rx="3" fill={fill} stroke={stroke} strokeWidth="2"/>;return <>{extra}{el}</>}
function edgeStyle(e){let rel=String(e.relation||'').toLowerCase();if(/operator|reference|cross/.test(rel))return ['#9F1239','6 4',2.2];if(/grant|permission|role/.test(rel))return ['#2557C4','',1.9];if(/produce|network|flow/.test(rel))return ['#0E6E70','2 4',1.7];if(/reconcile/.test(rel))return ['#6D4AC9','3 3',1.7];return ['#93A3B8','',1.5]}
const edgeKey=(a,b)=>`${a}\u0000${b}`;
const systemNamespace = value => /^(kube-system|kube-public|kube-node-lease|local-path-storage|default)$/.test(value);
// Show a bounded, connected analyst view of large inventories. Never discard the full scan.
function chooseFocus(nodes,edges,paths,findings,limit=30){
 if(nodes.length<=limit)return new Set(nodes.map(n=>n.id));
 const byId=new Map(nodes.map(n=>[n.id,n]));
 const adj=new Map(nodes.map(n=>[n.id,new Set()]));
 for(const e of edges){if(adj.has(e.source)&&adj.has(e.target)){adj.get(e.source).add(e.target);adj.get(e.target).add(e.source)}}
 const weight=new Map(nodes.map(n=>[n.id,0]));
 for(const p of paths){for(const id of p.nodes||[])if(weight.has(id))weight.set(id,weight.get(id)+70)}
 for(const f of findings){const resources=[f.resource,f.resource_id,f.node_id,...(f.nodes||[])].filter(x=>typeof x==='string');for(const id of resources){if(weight.has(id))weight.set(id,weight.get(id)+20)}}
 for(const n of nodes){const id=n.id;const d=adj.get(id).size;const k=kind(n);const bonus=systemNamespace(ns(n))?-14:12;const specific=/Binding|Role|ServiceAccount|CustomResource|Issuer|Secret|NetworkPolicy/.test(k)?10:0;weight.set(id,weight.get(id)+bonus+specific+Math.min(d,6)*2-Math.max(0,d-18)*.25)}
 const ranked=[...nodes].sort((a,b)=>weight.get(b.id)-weight.get(a.id)||a.id.localeCompare(b.id));
 const selected=new Set();const add=id=>{if(byId.has(id)&&selected.size<limit)selected.add(id)};
 const seed=ranked.find(n=>!systemNamespace(ns(n)))||ranked[0];add(seed.id);
 // Expand locally from meaningful nodes; avoid a 'hairball' made from unrelated hubs.
 let frontier=[seed.id];while(selected.size<limit&&frontier.length){const candidates=[...new Set(frontier.flatMap(id=>[...(adj.get(id)||[])]))].filter(id=>!selected.has(id));candidates.sort((a,b)=>weight.get(b)-weight.get(a)||a.localeCompare(b));const next=candidates.slice(0,Math.min(5,limit-selected.size));if(!next.length)break;next.forEach(add);frontier=next}
 for(const n of ranked)if(selected.size<limit)add(n.id);
 return selected;
}

// Layout uses generous, label-aware spacing in WORLD coordinates, never squeezes
// positions into the visible SVG. Components get their own lanes; connected
// resources are layered using a deterministic breadth-first traversal.
function spaciousLayout(nodes,edges){
 const ids=new Set(nodes.map(n=>n.id)), byId=new Map(nodes.map(n=>[n.id,n]));
 const adj=new Map([...ids].map(id=>[id,new Set()]));
 for(const e of edges)if(ids.has(e.source)&&ids.has(e.target)){adj.get(e.source).add(e.target);adj.get(e.target).add(e.source)}
 const components=[],seen=new Set();
 for(const id of [...ids].sort())if(!seen.has(id)){
   const stack=[id],members=[];seen.add(id);
   while(stack.length){const v=stack.pop();members.push(v);for(const w of [...adj.get(v)].sort())if(!seen.has(w)){seen.add(w);stack.push(w)}}
   components.push(members);
 }
 components.sort((a,b)=>b.length-a.length||a[0].localeCompare(b[0]));
 const loc={};let top=70;
 for(const component of components){
   const ranked=component.slice().sort((a,b)=>adj.get(b).size-adj.get(a).size||a.localeCompare(b));
   const root=ranked[0],depth=new Map([[root,0]]),queue=[root];
   for(let i=0;i<queue.length;i++){let v=queue[i];for(const w of [...adj.get(v)].sort())if(!depth.has(w)){depth.set(w,depth.get(v)+1);queue.push(w)}}
   const levels=new Map();for(const id of component){const d=depth.get(id)||0;if(!levels.has(d))levels.set(d,[]);levels.get(d).push(id)}
   const maxLevel=Math.max(...levels.keys());let tallest=0;
   for(const [level,items] of [...levels].sort((a,b)=>a[0]-b[0])){
      items.sort((a,b)=>ns(byId.get(a)).localeCompare(ns(byId.get(b)))||a.localeCompare(b));
      // More than 9 items at a level: split into readable rows, not a pile.
      const cols=Math.min(9,Math.max(1,items.length));const rows=Math.ceil(items.length/cols);
      const availableColumns=Math.max(5,cols);
      items.forEach((id,i)=>{const c=i%cols,r=Math.floor(i/cols);
         loc[id]={x:100+level*310+c*8+(r%2)*10,y:top+c*150+r*availableColumns*150};
      });
      tallest=Math.max(tallest,(cols-1)*150+(rows-1)*availableColumns*150+160);
   }
   // avoid huge empty component gaps but separate component captions cleanly
   top+=Math.max(205,tallest)+100;
 }
 return loc;
}
export default function AttackGraph({nodes=[],edges=[],attackPaths=[],transitions=[],findings=[],layoutPositions={},isSample=false}){
 const [selected,setSelected]=useState(null),[hover,setHover]=useState(null),[zoom,setZoom]=useState(1),[offset,setOffset]=useState({x:0,y:0}),[search,setSearch]=useState(''),[namespace,setNamespace]=useState('all'),[pathId,setPathId]=useState(''),[crossOnly,setCrossOnly]=useState(false),[labels,setLabels]=useState(false),[viewMode,setViewMode]=useState('focus'),[expanded,setExpanded]=useState(new Set());
 const host=useRef(null),pan=useRef(null),[width,setWidth]=useState(930);
 useEffect(()=>{if(!host.current)return;const ro=new ResizeObserver(([r])=>setWidth(Math.max(400,r.contentRect.width)));ro.observe(host.current);return ()=>ro.disconnect()},[]);
 const paths=useMemo(()=>[...attackPaths,...transitions],[attackPaths,transitions]);const active=paths.find(p=>String(p.id)===pathId),hot=new Set(active?.nodes||[]),hotEdges=new Set((active?.nodes||[]).slice(1).map((id,i)=>edgeKey(active.nodes[i],id)));
 const namespaceNames=[...new Set(nodes.map(ns))].sort();
 const focusedIds=useMemo(()=>chooseFocus(nodes,edges,paths,findings,30),[nodes,edges,paths,findings]);
 useEffect(()=>{setViewMode('focus');setExpanded(new Set());setSelected(null)},[nodes]);
 const neighborhood=()=>{const id=selected?.type==='node'?selected.id:hover;if(!id)return;const more=new Set(expanded);more.add(id);for(const e of edges){if(e.source===id)more.add(e.target);if(e.target===id)more.add(e.source)}setExpanded(more)};

 const visible=useMemo(()=>{let a=nodes.filter(n=>(viewMode==='all'||focusedIds.has(n.id)||expanded.has(n.id))&&(namespace==='all'||ns(n)===namespace));if(search.trim())a=a.filter(n=>(n.id+' '+label(n)+' '+kind(n)).toLowerCase().includes(search.toLowerCase()));if(crossOnly){const valid=new Set(edges.filter(e=>{const x=nodes.find(n=>n.id===e.source),y=nodes.find(n=>n.id===e.target);return x&&y&&ns(x)!==ns(y)}).flatMap(e=>[e.source,e.target]));a=a.filter(n=>valid.has(n.id))}return a},[nodes,edges,namespace,search,crossOnly,viewMode,focusedIds,expanded]);
 const links=useMemo(()=>{const ids=new Set(visible.map(n=>n.id));return edges.filter(e=>ids.has(e.source)&&ids.has(e.target))},[visible,edges]);
 const xy=useMemo(()=>spaciousLayout(visible,links),[visible,links]);
 const camera=useMemo(()=>{const p=Object.values(xy);if(!p.length)return {cx:0,cy:0,fit:1};const minX=Math.min(...p.map(v=>v.x)),maxX=Math.max(...p.map(v=>v.x)),minY=Math.min(...p.map(v=>v.y)),maxY=Math.max(...p.map(v=>v.y));return {cx:(minX+maxX)/2,cy:(minY+maxY)/2,fit:Math.min(1,(width-120)/Math.max(340,maxX-minX+180), (610-140)/Math.max(300,maxY-minY+110))}},[xy,width]);
 const factor=camera.fit*zoom;
 const screenPoint=p=>({x:width/2+offset.x+(p.x-camera.cx)*factor,y:305+offset.y+(p.y-camera.cy)*factor});
 const [pins,setPins]=useState({});useEffect(()=>setPins({}),[nodes]);const pts=Object.fromEntries(visible.map(n=>[n.id,pins[n.id]||xy[n.id]]));
 const focus=hover|| (selected?.type==='node'?selected.id:null);const near=new Set([focus]);if(focus)for(const e of links){if(e.source===focus)near.add(e.target);if(e.target===focus)near.add(e.source)}
 const crossCount=links.filter(e=>{const a=nodes.find(n=>n.id===e.source),b=nodes.find(n=>n.id===e.target);return a&&b&&ns(a)!==ns(b)}).length;
 const chosenNode=selected?.type==='node'?nodes.find(n=>n.id===selected.id):null,chosenEdge=selected?.type==='edge'?edges.find((e,i)=>i===selected.index):null;
 function down(e,id){if(e.button!==0)return;e.preventDefault();e.stopPropagation();const r=host.current.getBoundingClientRect();const px=camera.cx+(e.clientX-r.left-width/2-offset.x)/factor,py=camera.cy+(e.clientY-r.top-305-offset.y)/factor;pan.current=id?{id,dx:pts[id].x-px,dy:pts[id].y-py}:{sx:e.clientX,sy:e.clientY,ox:offset.x,oy:offset.y};e.currentTarget.setPointerCapture(e.pointerId)}
 function move(e){if(!pan.current)return;const p=pan.current;if(p.id){const r=host.current.getBoundingClientRect();setPins(v=>({...v,[p.id]:{x:camera.cx+(e.clientX-r.left-width/2-offset.x)/factor+p.dx,y:camera.cy+(e.clientY-r.top-305-offset.y)/factor+p.dy}}))}else setOffset({x:p.ox+e.clientX-p.sx,y:p.oy+e.clientY-p.sy})}
 return <section className="reference-topology">
 <div className="topology-toolbar"><strong>Attack-path topology</strong><span className="mode-tag">{isSample?'SAMPLE FIXTURE · NOT LIVE':'CURRENT SCAN · NETWORKX'}</span><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Find resource…" aria-label="Search resources"/><select value={namespace} onChange={e=>setNamespace(e.target.value)} aria-label="Namespace"><option value="all">All namespaces</option>{namespaceNames.map(x=><option key={x} value={x}>{x}</option>)}</select><label><input type="checkbox" checked={crossOnly} onChange={e=>setCrossOnly(e.target.checked)}/> Cross-namespace only</label><label><input type="checkbox" checked={labels} onChange={e=>setLabels(e.target.checked)}/> Edge labels</label></div>
 <div className="topology-toolbar"><span className="topology-view-switch"><button className={viewMode==='focus'?'active':''} onClick={()=>setViewMode('focus')}>Focused topology</button><button className={viewMode==='all'?'active':''} onClick={()=>setViewMode('all')}>Full inventory ({nodes.length})</button></span><button className="topology-expand" onClick={neighborhood} disabled={!selected||selected.type!=='node'}>Expand neighbors</button><span>Highlight candidate path:</span><select value={pathId} onChange={e=>{setPathId(e.target.value);setSelected(null)}}><option value="">All relationships</option>{paths.map((p,i)=><option key={i} value={p.id}>{p.rule||p.id||`Path ${i+1}`}</option>)}</select><span className="topology-hint">Spacious world layout · Pan and zoom around graph center</span></div>
 <div className="topology-layout"><div className="topology-canvas" ref={host} onPointerMove={move} onPointerUp={()=>pan.current=null} onPointerCancel={()=>pan.current=null}>
 <div className="topology-stats"><span>{visible.length} / {nodes.length} nodes</span><span>{links.length} / {edges.length} edges</span><span className={crossCount?'cross':''}>{crossCount} cross-namespace</span></div><div className="topology-controls"><button title="Zoom in" onClick={()=>setZoom(v=>Math.min(250,v*1.35))}>＋</button><button title="Zoom out" onClick={()=>setZoom(v=>Math.max(.08,v/1.35))}>−</button><button title="Reset view" onClick={()=>{setZoom(1);setOffset({x:0,y:0});setPins({})}}>⤢</button></div>
 <svg width="100%" height="610" viewBox={`0 0 ${width} 610`} onPointerDown={e=>down(e)} aria-label="Interactive Kubernetes attack-path graph" role="img"><defs>{['gray','red','blue','green','violet'].map((k,i)=><marker key={k} id={`ref-arrow-${k}`} markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto"><path d="M0 0 L7 3.5 L0 7Z" fill={['#93A3B8','#9F1239','#2557C4','#0E6E70','#6D4AC9'][i]}/></marker>)}</defs><g transform={`translate(${width/2+offset.x},${305+offset.y}) scale(${factor}) translate(${-camera.cx},${-camera.cy})`}>
 {namespaceNames.filter(x=>visible.filter(n=>ns(n)===x).length>=2).map(x=>{const a=visible.filter(n=>ns(n)===x).map(n=>pts[n.id]);return <text key={x} className="topology-namespace" x={Math.min(...a.map(p=>p.x))} y={Math.max(48,Math.min(...a.map(p=>p.y))-32)}>{x}</text>})}
 {links.map((e,i)=>{const a=pts[e.source],b=pts[e.target];if(!a||!b)return null;const [col,dash,w]=edgeStyle(e),cross=ns(nodes.find(n=>n.id===e.source))!==ns(nodes.find(n=>n.id===e.target));const hotEdge=hotEdges.has(edgeKey(e.source,e.target));const dx=b.x-a.x,dy=b.y-a.y,len=Math.hypot(dx,dy)||1;const bx=b.x-dx/len*21,by=b.y-dy/len*21;const marker=hotEdge?'red':col==='#2557C4'?'blue':col==='#0E6E70'?'green':col==='#6D4AC9'?'violet':cross?'red':'gray';const fade=focus&&e.source!==focus&&e.target!==focus;return <g key={i} opacity={fade?0.08:1} className="topology-edge" onClick={ev=>{ev.stopPropagation();setSelected({type:'edge',index:edges.indexOf(e)})}}><line x1={a.x} y1={a.y} x2={bx} y2={by} stroke={hotEdge?'#9F1239':cross?'#9F1239':col} strokeWidth={hotEdge?3.5:cross?2.5:w} strokeDasharray={dash||undefined} markerEnd={`url(#ref-arrow-${marker})`}/><line x1={a.x} y1={a.y} x2={bx} y2={by} stroke="transparent" strokeWidth="15"/>{(labels||(cross&&visible.length<=34))&&<text x={(a.x+bx)/2} y={(a.y+by)/2-7} textAnchor="middle" className="topology-edge-label">{String(e.relation||'references').replaceAll('_',' ').slice(0,26)}</text>}</g>})}
 {visible.map(n=>{const p=pts[n.id],isFocus=focus===n.id,dim=focus&&!near.has(n.id);return <g key={n.id} className="topology-node" opacity={dim?0.13:1} onPointerDown={e=>down(e,n.id)} onPointerEnter={()=>setHover(n.id)} onPointerLeave={()=>setHover(null)} onClick={e=>{e.stopPropagation();setSelected(v=>v?.id===n.id?null:{type:'node',id:n.id})}}>{ns(n)==='cluster'&&<circle cx={p.x} cy={p.y} r={cfg(n)[3]+5} stroke="#9F1239" strokeDasharray="2 3" fill="none"/>}<Shape node={n} x={p.x} y={p.y} chosen={selected?.id===n.id||hot.has(n.id)}/><text className="topology-node-label" x={p.x} y={p.y+cfg(n)[3]+14} textAnchor="middle">{label(n).length>23?label(n).slice(0,21)+'…':label(n)}</text><title>{n.id}</title></g>})}
 </g></svg>{hover&&pts[hover]&&<div className="topology-hover" style={{left:Math.min(width-210,Math.max(12,screenPoint(pts[hover]).x+18)),top:Math.min(510,Math.max(40,screenPoint(pts[hover]).y-58))}}><b>{label(nodes.find(n=>n.id===hover)||{id:hover})}</b><span>{kind(nodes.find(n=>n.id===hover)||{id:hover})} · {ns(nodes.find(n=>n.id===hover)||{id:hover})}</span><small>Click to inspect · drag to reposition</small></div>}<div className="topology-legend"><b>Legend</b><span><i className="sw red"/>Cross-namespace / reference</span><span><i className="sw blue"/>RBAC grant</span><span><i className="sw gray"/>Binding / relation</span><span><i className="sw green"/>Produced / network</span><span><i className="sw scope"/>Cluster scoped resource</span></div>
 </div><aside className="topology-inspector"><header><strong>Resource inspector</strong><span>SECURITY EVIDENCE</span></header>{chosenNode?<><div className="inspector-title">{label(chosenNode)}</div><p>{kind(chosenNode)} · {ns(chosenNode)}</p><code>{chosenNode.id}</code><h4>Connected relationships</h4>{edges.filter(e=>e.source===chosenNode.id||e.target===chosenNode.id).map((e,i)=><div className="inspector-evidence" key={i}><b>{e.relation}</b><small>{e.source===chosenNode.id?e.target:e.source}</small></div>)}<h4>Associated findings</h4>{findings.filter(f=>JSON.stringify(f).includes(chosenNode.id)).map((f,i)=><div className="inspector-evidence" key={i}><b>{f.rule}</b><small>{f.description}</small></div>)}<details><summary>Raw evidence</summary><pre>{JSON.stringify(chosenNode,null,2)}</pre></details></>:chosenEdge?<><div className="inspector-title">{chosenEdge.relation||'Relationship'}</div><p>From</p><code>{chosenEdge.source}</code><p>To</p><code>{chosenEdge.target}</code><details open><summary>Graph evidence</summary><pre>{JSON.stringify(chosenEdge,null,2)}</pre></details></>:active?<><div className="inspector-title">{active.rule||'Candidate capability path'}</div><p>{active.description}</p>{(active.nodes||[]).map((n,i)=><div className="inspector-evidence" key={i}>{i+1}. {n}</div>)}<small>Inferred capability, not confirmed exploitation</small></>:<div className="inspector-empty"><strong>Inspect a resource</strong><p>Select a topology node or relationship to view its Kubernetes identity and scanner evidence. Select a path above to highlight a potential attack progression.</p></div>}</aside></div>
 {viewMode==='all'&&nodes.length>100&&<div className="topology-warning">Full inventory contains {nodes.length} resources. Zoom in or select a namespace for individual labels and relationships.</div>}<div className="topology-foot">{isSample?'Preloaded analysis fixture: operator_and_paths.yaml. This example is not a live-cluster finding.':'Graph data comes from the latest scan; layout calculated by NetworkX when supplied by the backend.'} · Relationships show static inferences, not observed attacks.</div></section>
}
