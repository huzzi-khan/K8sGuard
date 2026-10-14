import React, { useMemo, useRef, useState } from 'react';
import './attack-graph.scss';

const groups = ['Namespace','Pod','Deployment','StatefulSet','DaemonSet','CronJob','ServiceAccount','RoleBinding','ClusterRoleBinding','Role','ClusterRole','Secret','NetworkPolicy','CustomResource','MitreTechnique'];
const category = n => String(n.kind || 'Resource');
const colorOf = kind => ({Pod:'#3879c7',Deployment:'#3879c7',StatefulSet:'#3879c7',DaemonSet:'#3879c7',ServiceAccount:'#239268',Role:'#b5751c',ClusterRole:'#b5751c',RoleBinding:'#c17e37',ClusterRoleBinding:'#c17e37',Secret:'#cd536a',MitreTechnique:'#7763a6'})[kind] || '#647e9a';
const labelOf = n => n.label || n.id;
const idOf = x => String(x || '');
const esc = x => String(x ?? '');

/** Graph nodes and edges come exclusively from the scan API. No sample risk data is synthesized here. */
export default function AttackGraph({nodes=[],edges=[],attackPaths=[],transitions=[],findings=[],layoutPositions={}}) {
  const [search,setSearch] = useState('');
  const [kindFilter,setKindFilter] = useState('all');
  const [selectedPath,setSelectedPath] = useState('');
  const [selection,setSelection] = useState(null);
  const [view,setView] = useState({x:30,y:30,k:1});
  const [hideSemantic,setHideSemantic] = useState(true);
  const svgRef=useRef(null), drag=useRef(null);
  const paths=useMemo(()=>[...transitions.map(t=>({...t,pathType:'Conditional transition'})),...attackPaths.map(p=>({...p,pathType:'Capability path'}))], [transitions,attackPaths]);
  const activePath=paths.find(p=>p.id===selectedPath);
  const includedIds=new Set((activePath?.nodes||[]).map(idOf));
  const pathEdges=new Set();
  for(let i=0;i<(activePath?.nodes?.length||0)-1;i++)pathEdges.add(`${activePath.nodes[i]}||${activePath.nodes[i+1]}`);
  const filtered=useMemo(()=>{
    const byId=new Map(nodes.map(n=>[n.id,n]));
    let visible=nodes.filter(n=>(!hideSemantic||!['MitreTechnique','CisControl'].includes(category(n)))&&(kindFilter==='all'||category(n)===kindFilter));
    const q=search.trim().toLowerCase();
    if(q){const matches=new Set(nodes.filter(n=>`${n.id} ${labelOf(n)} ${category(n)}`.toLowerCase().includes(q)).map(n=>n.id));
      visible=visible.filter(n=>matches.has(n.id)||edges.some(e=>(matches.has(e.source)&&e.target===n.id)||(matches.has(e.target)&&e.source===n.id)));
    }
    if(activePath)for(const id of includedIds){const n=byId.get(id);if(n&&!visible.some(v=>v.id===id))visible.push(n);}
    const ids=new Set(visible.map(n=>n.id));
    const visibleEdges=edges.filter(e=>ids.has(e.source)&&ids.has(e.target)&&(!hideSemantic||!e.semantic_only));
    return {visible,visibleEdges};
  },[nodes,edges,search,kindFilter,hideSemantic,activePath]);
  const layout=useMemo(()=>{
    const point=new Map();let maxX=0,maxY=0;
    const order=new Map(groups.map((k,i)=>[k,i]));
    const fallback=[...filtered.visible].sort((a,b)=>(order.get(category(a))??100)-(order.get(category(b))??100)||a.id.localeCompare(b.id));
    fallback.forEach((n,i)=>{
      const raw=layoutPositions[n.id];
      const x=raw && Number.isFinite(Number(raw.x)) ? Number(raw.x)+110 : 140+(i%7)*215;
      const y=raw && Number.isFinite(Number(raw.y)) ? Number(raw.y)+80 : 100+Math.floor(i/7)*115;
      point.set(n.id,{x,y});maxX=Math.max(maxX,x);maxY=Math.max(maxY,y);
    });
    return {point,width:maxX+160,height:maxY+100};
  },[filtered.visible,layoutPositions]);
  const selectedNode=selection?.type==='node'?nodes.find(n=>n.id===selection.id):null;
  const selectedEdge=selection?.type==='edge'?edges.find((e,i)=>String(i)===selection.id):null;
  function zoom(mult){setView(v=>({...v,k:Math.max(.15,Math.min(3,v.k*mult))}));}
  function onWheel(e){if(!e.ctrlKey&&!e.metaKey)return;e.preventDefault();zoom(e.deltaY<0?1.12:.89);}
  function pointerDown(e){if(e.target.closest('[data-graph-node]'))return;drag.current={x:e.clientX,y:e.clientY,ox:view.x,oy:view.y};e.currentTarget.setPointerCapture(e.pointerId);}
  function pointerMove(e){if(!drag.current)return;setView(v=>({...v,x:drag.current.ox+e.clientX-drag.current.x,y:drag.current.oy+e.clientY-drag.current.y}));}
  function fit(){const available=Math.max(420,svgRef.current?.clientWidth||900);const height=svgRef.current?.clientHeight||520;const k=Math.min(1.5,Math.max(.15,Math.min((available-60)/layout.width,(height-60)/layout.height)));setView({k,x:30,y:30});}
  const edgeKinds=[...new Set(edges.map(e=>e.relation).filter(Boolean))].sort();
  const categories=[...new Set(nodes.map(category))].sort();
  return <div className="attack-explorer">
    <div className="graph-heading"><div><span className="graph-overline">K8SGUARD / GRAPH EXPLORER</span><h3>Resource topology &amp; attack paths</h3><p>NetworkX-computed topology · Kubernetes API evidence</p></div><div className="graph-counts"><span>{nodes.length} resources</span><span>{edges.length} links</span><span>{paths.length} paths</span></div></div><div className="graph-toolbar">
      <input aria-label="Search graph resources" placeholder="Search resources or IDs" value={search} onChange={e=>setSearch(e.target.value)}/>
      <select aria-label="Filter node type" value={kindFilter} onChange={e=>setKindFilter(e.target.value)}><option value="all">All resource types</option>{categories.map(c=><option key={c}>{c}</option>)}</select>
      <label className="graph-check"><input type="checkbox" checked={hideSemantic} onChange={e=>setHideSemantic(e.target.checked)}/> Hide reference-only edges</label>
    </div>
    <div className="graph-toolbar"><select className="path-picker" aria-label="Highlight attack path" value={selectedPath} onChange={e=>{setSelectedPath(e.target.value);setSelection(null);}}><option value="">All paths (no highlight)</option>{paths.map(p=><option key={`${p.pathType}-${p.id}`} value={p.id}>{p.id}: {p.rule||p.description||p.pathType}</option>)}</select><button type="button" onClick={()=>zoom(1.25)}>Zoom +</button><button type="button" onClick={()=>zoom(.8)}>Zoom −</button><button type="button" onClick={fit}>Fit graph</button><button type="button" onClick={()=>{setView({x:30,y:30,k:1});setSearch('');setSelectedPath('');setKindFilter('all');setSelection(null);}}>Reset</button></div>
    <div className="graph-instructions">Drag background to pan. Hold Ctrl and scroll to zoom, or use the zoom controls. Select a node or edge to inspect evidence.</div>
    <div className="graph-workspace">
      <svg ref={svgRef} className="graph-canvas" onPointerDown={pointerDown} onPointerMove={pointerMove} onPointerUp={()=>drag.current=null} onPointerCancel={()=>drag.current=null} onWheel={onWheel} aria-label="Interactive Kubernetes resource and attack-path graph" role="img">
        <defs><marker id="k8arrow" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8 Z" fill="#6884a4"/></marker><marker id="k8arrowhot" markerWidth="8" markerHeight="8" refX="7" refY="4" orient="auto"><path d="M0 0 L8 4 L0 8 Z" fill="#ff6d70"/></marker></defs>
        <g transform={`translate(${view.x} ${view.y}) scale(${view.k})`}>
        {filtered.visibleEdges.map((e,i)=>{const s=layout.point.get(e.source),t=layout.point.get(e.target);if(!s||!t)return null;const hot=pathEdges.has(`${e.source}||${e.target}`);const idx=edges.indexOf(e);const selected=selection?.type==='edge'&&selection.id===String(idx);return <g key={`${e.source}-${e.target}-${i}`} onClick={ev=>{ev.stopPropagation();setSelection({type:'edge',id:String(idx)});}} style={{cursor:'pointer'}}><path d={`M${s.x+74},${s.y} C${s.x+(t.x-s.x)*.4},${s.y} ${t.x-(t.x-s.x)*.4},${t.y} ${t.x-74},${t.y}`} fill="none" stroke={hot?'#ff6d70':selected?'#c3fa8e':'#617b96'} strokeWidth={hot||selected?3.7:1.5} strokeDasharray={e.semantic_only?'7 5':undefined} markerEnd={`url(#${hot?'k8arrowhot':'k8arrow'})`}/><title>{`${e.source} → ${e.relation} → ${e.target}`}</title></g>})}
        {filtered.visible.map(n=>{const p=layout.point.get(n.id);if(!p)return null;const isSelected=selection?.type==='node'&&selection.id===n.id;const hot=includedIds.has(n.id);return <g data-graph-node="true" key={n.id} onClick={e=>{e.stopPropagation();setSelection({type:'node',id:n.id});}} style={{cursor:'pointer'}}><rect x={p.x-75} y={p.y-28} width="150" height="56" rx="9" fill={isSelected?'#dceefa':'#ffffff'} stroke={hot?'#ff6d70':isSelected?'#c3fa8e':colorOf(category(n))} strokeWidth={hot||isSelected?3:1.3}/><text x={p.x} y={p.y-8} fill={colorOf(category(n))} textAnchor="middle" fontSize="11">{category(n)}</text><text x={p.x} y={p.y+12} fill="#263951" textAnchor="middle" fontSize="11">{labelOf(n).slice(0,21)}</text><title>{n.id}</title></g>})}
        </g>
      </svg>
      <div className="graph-inspector"><h3>Evidence inspector</h3><p className="inspect-caption">Explore the selected entity and its real scan evidence.</p>{selectedNode?<><b>{labelOf(selectedNode)}</b><p>{category(selectedNode)}</p><code>{selectedNode.id}</code><h4>Related edges</h4>{edges.filter(e=>e.source===selectedNode.id||e.target===selectedNode.id).map((e,i)=><div className="inspector-record" key={i}><small>{e.relation}</small><span>{e.source===selectedNode.id?e.target:e.source}</span></div>)}<h4>Associated findings</h4>{findings.filter(f=>JSON.stringify(f).includes(selectedNode.id)||JSON.stringify(f).includes(labelOf(selectedNode))).map(f=><div className="inspector-record" key={f.id}>{f.rule} ({f.severity})</div>)}</>:selectedEdge?<><strong>{selectedEdge.relation}</strong><p>{selectedEdge.source} → {selectedEdge.target}</p><pre>{JSON.stringify(selectedEdge,null,2)}</pre></>:activePath?<><strong>{activePath.rule}</strong><p>{activePath.pathType} · {activePath.severity||'unranked'}</p><ol>{(activePath.nodes||[]).map((id,i)=><li key={i}>{id}</li>)}</ol><p>{activePath.description||activePath.possible_effect}</p>{activePath.preconditions?.map((x,i)=><div className="inspector-record" key={i}>{x}</div>)}<small>This is a conditional path, not observed exploitation.</small></>:<p>Select a node, edge or attack path to explore its supporting data.</p>}</div>
    </div><div className="graph-legend"><span><i style={{background:"#3d73c4"}}/> Workloads</span><span><i style={{background:"#239268"}}/> Identity</span><span><i style={{background:"#df9641"}}/> Authorization</span><span><i style={{background:"#d64e5c"}}/> Attack path</span></div><div className="graph-summary">Showing {filtered.visible.length} of {nodes.length} nodes and {filtered.visibleEdges.length} of {edges.length} edges. {paths.length} candidate paths. Framework annotation edges are not attack steps.</div>
  </div>;
}
