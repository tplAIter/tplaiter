// Package graphview renders a graph document as a self-contained local page.
package graphview

import (
	"encoding/json"
	"errors"
	"html/template"
	"strings"

	"github.com/tplAIter/tplaiter/internal/contextpack"
	"github.com/tplAIter/tplaiter/internal/deps"
	"github.com/tplAIter/tplaiter/internal/exports"
	"github.com/tplAIter/tplaiter/internal/graphdoc"
)

type Options struct {
	Title   string
	Context *contextpack.Pack
}
type ApplicationRelation struct {
	From     string `json:"from"`
	To       string `json:"to"`
	Kind     string `json:"kind"`
	Evidence string `json:"evidence"`
	Declared bool   `json:"declared"`
	Detected bool   `json:"detected"`
}

// FromContracts projects pinned source/export contracts and only supplied,
// attributed application relations. It never infers calls from syntax.
func FromContracts(source *deps.SourceGraph, selected *exports.ExportGraph, app []ApplicationRelation) (graphdoc.Document, error) {
	if source == nil {
		return graphdoc.Document{}, errors.New("graphview: nil source graph")
	}
	if err := deps.ValidateSourceGraph(source); err != nil {
		return graphdoc.Document{}, err
	}
	d := graphdoc.New()
	d.Layer = "source-export"
	d.Producer = "tplaiter graphview contracts"
	known := map[string]bool{}
	for _, n := range source.Nodes {
		id := "source:" + n.Key
		known[id] = true
		d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "source", Name: n.Identity.ProviderID, Attributes: map[string]string{"contentDigest": n.Identity.ContentDigest, "treeDigest": n.Identity.TreeDigest}, Provenance: []graphdoc.Provenance{{Source: "deps.SourceGraph", Evidence: n.Identity.ContentDigest, Declared: true}}})
	}
	for _, e := range source.Edges {
		d.Edges = append(d.Edges, graphdoc.Edge{From: "source:" + e.Dependency, To: "source:" + e.Consumer, Kind: "dependency", Provenance: []graphdoc.Provenance{{Source: "deps.SourceGraph", Evidence: source.Digest, Declared: true}}})
	}
	if selected != nil {
		for _, s := range selected.Selected {
			id := "export:" + s.ID
			known[id] = true
			d.Nodes = append(d.Nodes, graphdoc.Node{ID: id, Kind: "export", Name: s.Name, Attributes: map[string]string{"source": s.Source, "provider": s.Provider, "contentDigest": s.ContentDigest}, Provenance: []graphdoc.Provenance{{Source: "exports.ExportGraph", Evidence: selected.Digest, Declared: true}}})
		}
		for _, e := range selected.Edges {
			d.Edges = append(d.Edges, graphdoc.Edge{From: "export:" + e.Dependency, To: "export:" + e.Consumer, Kind: "export-dependency", Provenance: []graphdoc.Provenance{{Source: "exports.ExportGraph", Evidence: selected.Digest, Declared: true}}})
		}
	}
	for _, r := range app {
		if !known[r.From] || !known[r.To] || r.Kind == "" || r.Evidence == "" || (!r.Declared && !r.Detected) {
			return graphdoc.Document{}, errors.New("graphview: invalid application relation")
		}
		d.Edges = append(d.Edges, graphdoc.Edge{From: r.From, To: r.To, Kind: r.Kind, Provenance: []graphdoc.Provenance{{Source: "application-relation", Evidence: r.Evidence, Declared: r.Declared, Detected: r.Detected}}})
	}
	if err := d.Canonicalize(); err != nil {
		return graphdoc.Document{}, err
	}
	return d, nil
}

func Render(d graphdoc.Document, opts Options) ([]byte, error) {
	if err := graphdoc.Verify(d); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(d)
	if err != nil {
		return nil, err
	}
	ctx := []byte("null")
	if opts.Context != nil {
		ctx, err = json.Marshal(opts.Context)
		if err != nil {
			return nil, err
		}
	}
	// Encode the compact Go wire text as a JavaScript string literal. The page
	// parses it for display but downloads this exact text, preserving Go's JSON
	// escaping and the byte count Build accounted for.
	ctxString, err := json.Marshal(string(ctx))
	if err != nil {
		return nil, err
	}
	title := opts.Title
	if title == "" {
		title = "tplAIter Graph Explorer"
	}
	page := `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Title}}</title><style>body{margin:0;font:14px system-ui;background:#101827;color:#e5e7eb}header{padding:12px;display:flex;gap:8px;flex-wrap:wrap;background:#1e293b}input,select,button,a{padding:7px;background:#0f172a;color:#e5e7eb;border:1px solid #64748b;border-radius:4px}main{display:grid;grid-template-columns:1fr 300px;height:calc(100vh - 64px)}svg{width:100%;height:100%;touch-action:none}aside{padding:12px;overflow:auto;border-left:1px solid #475569}.n{cursor:pointer}.n text{fill:white;font-size:11px}.e{stroke:#94a3b8;marker-end:url(#arrow)}@media(max-width:700px){main{display:block;height:auto}svg{height:62vh}aside{border-left:0;border-top:1px solid #475569;min-height:180px}}</style><header><b>{{.Title}}</b><input id=q placeholder="Search"><select id=k><option value="">All types</option></select><select id=dir><option value=both>Both</option><option value=out>Outgoing</option><option value=in>Incoming</option></select><label>Depth <input id=depth type=number min=0 value=3 size=2></label><button id=graphDownload>Download graph JSON</button><button id=packDownload>Download context pack</button><span id=stats></span></header><main><svg id=g viewBox="0 0 1000 650" aria-label="Interactive graph"></svg><aside id=info>Select a node.</aside></main><script>const DATA={{.Graph}},PACK={{.Context}},g=document.querySelector('#g'),info=document.querySelector('#info'),q=document.querySelector('#q'),k=document.querySelector('#k'),dir=document.querySelector('#dir'),depth=document.querySelector('#depth');let chosen='';for(const x of [...new Set(DATA.nodes.map(n=>n.kind))].sort()){k.insertAdjacentHTML('beforeend','<option>'+x+'</option>')}const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));function visible(){let ns=DATA.nodes.filter(n=>(!q.value||JSON.stringify(n).toLowerCase().includes(q.value.toLowerCase()))&&(!k.value||n.kind===k.value)),ids=new Set(ns.map(n=>n.id)),es=DATA.edges.filter(e=>ids.has(e.from)&&ids.has(e.to)),root=chosen&&ids.has(chosen)?chosen:(ns[0]||{}).id,seen=new Map(root?[[root,0]]:[]),lim=Math.max(0,+depth.value||0);for(let d=0;d<lim;d++)for(const e of es){if(dir.value!=='in'&&seen.get(e.from)===d&&!seen.has(e.to))seen.set(e.to,d+1);if(dir.value!=='out'&&seen.get(e.to)===d&&!seen.has(e.from))seen.set(e.from,d+1)}if(root){ns=ns.filter(n=>seen.has(n.id));ids=new Set(ns.map(n=>n.id));es=es.filter(e=>ids.has(e.from)&&ids.has(e.to))}return[ns,es]}function draw(){const[ns,es]=visible(),pos=new Map(ns.map((n,i)=>[n.id,{x:80+(i%7)*135,y:70+Math.floor(i/7)*110}]));let out='<defs><marker id=arrow markerWidth=8 markerHeight=8 refX=7 refY=3 orient=auto><path d="M0,0L0,6L7,3" fill="#94a3b8"/></marker></defs>';for(const e of es){let a=pos.get(e.from),b=pos.get(e.to);out+='<line class=e x1='+a.x+' y1='+a.y+' x2='+b.x+' y2='+b.y+' />'}for(const n of ns){let p=pos.get(n.id);out+='<g class=n data-id="'+esc(n.id)+'" transform="translate('+p.x+','+p.y+')"><circle r=21 fill="#2563eb"/><text y=38 text-anchor=middle>'+esc(n.name||n.kind)+'</text></g>'}g.innerHTML=out;document.querySelector('#stats').textContent=ns.length+' nodes / '+es.length+' relations';g.querySelectorAll('.n').forEach(x=>x.onclick=()=>pick(x.dataset.id))}function pick(id){chosen=id;let n=DATA.nodes.find(x=>x.id===id),rs=DATA.edges.filter(e=>e.from===id||e.to===id);info.innerHTML='<h2>'+esc(n.name||n.kind)+'</h2><p>'+esc(n.id)+'</p><p>'+esc(n.path||'')+'</p><h3>Provenance</h3>'+((n.provenance||[]).map(p=>'<p>'+esc(p.source)+' · '+esc(p.evidence)+'</p>').join('')||'none')+'<h3>Relations</h3>'+rs.map(e=>'<p>'+esc(e.kind)+' '+esc(e.from===id?'→ '+e.to:'← '+e.from)+'</p>').join('');draw()}for(const x of[q,k,dir,depth])x.oninput=draw;function save(name,v){let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([JSON.stringify(v,null,2)],{type:'application/json'}));a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),0)}document.querySelector('#graphDownload').onclick=()=>save('graph.json',DATA);document.querySelector('#packDownload').onclick=()=>PACK&&save('context-pack.json',PACK);document.querySelector('#packDownload').disabled=!PACK;let zoom=1;g.onwheel=e=>{e.preventDefault();zoom=Math.max(.4,Math.min(2,zoom+(e.deltaY<0?.1:-.1)));g.style.transform='scale('+zoom+')';g.style.transformOrigin='center'};draw()</script>`
	// The context pack cap is over compact UTF-8 JSON. The browser must not
	// change that representation by pretty-printing it after Build accounted it.
	page = strings.ReplaceAll(page, "PACK={{.Context}}", "PACK_RAW={{.ContextRaw}},PACK=PACK_RAW?JSON.parse(PACK_RAW):null")
	page = strings.ReplaceAll(page, "Download context pack", "Download CLI-selected context pack")
	page = strings.ReplaceAll(page, "id=packDownload>Download CLI-selected context pack", "id=packDownload aria-label=\"Download context pack\">Download CLI-selected context pack")
	page = strings.ReplaceAll(page, "<span id=stats></span>", "<span id=stats></span><span id=prepared></span>")
	page = strings.ReplaceAll(page, "aside{padding:12px;overflow:auto", "aside{padding:12px;overflow:auto;overflow-wrap:anywhere")
	page = strings.ReplaceAll(page, "JSON.stringify(v,null,2)", "JSON.stringify(v)")
	page = strings.ReplaceAll(page, "document.querySelector('#packDownload').onclick=()=>PACK&&save('context-pack.json',PACK)", "document.querySelector('#packDownload').onclick=()=>{if(!PACK)return;const n=new TextEncoder().encode(PACK_RAW).byteLength;if(n!==PACK.bytes||n>32768)throw new Error('context pack accounting mismatch');let a=document.createElement('a');a.href=URL.createObjectURL(new Blob([PACK_RAW],{type:'application/json'}));a.download='context-pack.json';a.click()}")
	page = strings.ReplaceAll(page, "document.querySelector('#packDownload').disabled=!PACK", "document.querySelector('#packDownload').disabled=!PACK;if(PACK)document.querySelector('#prepared').textContent='CLI-selected: '+PACK.nodes.map(n=>n.id).join(', ')+' · '+PACK.bytes+' bytes'")
	t := template.Must(template.New("page").Parse(page))
	var b strings.Builder
	err = t.Execute(&b, struct {
		Title      string
		Graph      template.JS
		ContextRaw template.JS
	}{title, template.JS(raw), template.JS(ctxString)}) //nolint:gosec // both values are json.Marshal output, which escapes <, > and &
	if err != nil {
		return nil, err
	}
	return []byte(b.String()), nil
}
