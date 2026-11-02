package render

import (
	"fmt"
	"sort"
	"strings"

	"github.com/Idris1980/lookfirst/internal/model"
)

// A network picture: when the code builds a virtual network (an Azure
// VNet or an AWS VPC), it is drawn the way Microsoft and Amazon draw their
// own architecture pictures, with boxes inside boxes. The network is a
// frame, each subnet a frame inside it, and the servers stand in their
// subnet. A security group is not a box of its own: its rules are written
// in the boxes it protects ("80, 443 from anyone"), and the arrows show
// only traffic, with the ports it may use: from the internet, from your
// own IP address, and from one group of servers to another.

const (
	framePad   = 16 // inside a network frame
	frameHead  = 40 // room for a network frame's name
	subnetPad  = 12
	subnetHead = 46 // its name, and room for arrows to come in under it
	memberGap  = 44 // between boxes in a subnet
	noteLine   = 13 // a line of rules under a box's name
	netGap     = 120
)

// netBox is a box in a network picture: a node, or someone outside such as
// "your IP".
type netBox struct {
	node       *model.Node
	x, y, h    int
	notes      []string
	publicIP   bool
	inside     string // the frame it stands in
	isActor    bool
	actorLabel string
}

type netFrame struct {
	id, title, sub, class string
	lines                 []string // the rules of the security groups on it
	x, y, w, h            int
	empty                 bool
}

type netArrow struct {
	from, to    string // box or frame ids
	label, kind string
	risky       bool
}

type netView struct {
	boxes  []*netBox
	byID   map[string]*netBox
	frames []*netFrame
	fbyID  map[string]*netFrame
	arrows []netArrow
	w, h   int
	// For the exports: which frame each frame and box stands in.
	parent map[string]string
}

func isVNet(n *model.Node) bool {
	f := strings.ToLower(n.Friendly)
	return n.Kind == "network" && (strings.Contains(f, "virtual network") || strings.HasPrefix(f, "vpc"))
}

func isGuard(n *model.Node) bool {
	return n.Kind == "shield" && strings.Contains(strings.ToLower(n.Friendly), "security group")
}

func isNIC(n *model.Node) bool {
	f := strings.ToLower(n.Friendly)
	return n.Kind == "nic" && (strings.Contains(f, "network interface") || strings.Contains(f, "network card"))
}

// buildNetwork lays out a network picture, or returns false when the code
// builds no virtual network.
func buildNetwork(g *model.Graph) (*netView, bool) {
	var vnets []*model.Node
	for _, n := range g.Nodes {
		if isVNet(n) && !n.Hidden {
			vnets = append(vnets, n)
		}
	}
	if len(vnets) == 0 {
		return nil, false
	}
	near := map[string][]string{} // lines in both directions, between boxes
	for _, e := range g.Edges {
		if e.From == model.InternetID || model.IsAddress(e.From) || e.Kind == model.Order || strings.Contains(e.Label, "only lets in traffic from") {
			continue // an access restriction is a rule, not where it stands
		}
		near[e.From] = append(near[e.From], e.To)
		near[e.To] = append(near[e.To], e.From)
	}
	nodeOf := func(id string) *model.Node { return g.Node(id) }
	neighbour := func(id string, ok func(*model.Node) bool) string {
		for _, m := range near[id] {
			if n := nodeOf(m); n != nil && ok(n) {
				return m
			}
		}
		return ""
	}
	isSubnet := func(n *model.Node) bool { return n.Kind == "subnet" && !n.Hidden }

	// Where each thing stands: subnets in networks, then everything else
	// in a subnet (also through its network card) or straight in a network.
	frameOf := map[string]string{}
	for _, n := range g.Nodes {
		if isSubnet(n) {
			frameOf[n.ID] = neighbour(n.ID, isVNet)
		}
	}
	nicIn := map[string]string{}
	for _, n := range g.Nodes {
		if isNIC(n) {
			if s := neighbour(n.ID, isSubnet); s != "" {
				nicIn[n.ID] = s
			} else {
				nicIn[n.ID] = neighbour(n.ID, isVNet)
			}
		}
	}
	member := func(n *model.Node) bool {
		switch {
		case n.Hidden, n.ID == model.InternetID, n.Cloud == "", isVNet(n), isSubnet(n), isGuard(n), isNIC(n),
			n.Kind == "publicip", n.Kind == "dns", n.Kind == "globe":
			return false
		}
		return true
	}
	for _, n := range g.Nodes {
		if !member(n) {
			continue
		}
		if s := neighbour(n.ID, isSubnet); s != "" {
			frameOf[n.ID] = s
		} else if nic := neighbour(n.ID, isNIC); nic != "" && nicIn[nic] != "" {
			frameOf[n.ID] = nicIn[nic]
		} else if v := neighbour(n.ID, isVNet); v != "" {
			frameOf[n.ID] = v
		}
	}

	// What each security group protects: boxes, directly or through their
	// network card, and subnets.
	protects := map[string][]string{}
	for _, gd := range g.Nodes {
		if !isGuard(gd) {
			continue
		}
		seen := map[string]bool{}
		for _, m := range near[gd.ID] {
			n := nodeOf(m)
			if n == nil {
				continue
			}
			target := ""
			switch {
			case isSubnet(n) && frameOf[m] != "":
				target = m
			case isNIC(n):
				for _, x := range near[m] {
					if xn := nodeOf(x); xn != nil && member(xn) && frameOf[x] != "" {
						target = x
					}
				}
			case member(n) && frameOf[m] != "":
				target = m
			}
			if target != "" && !seen[target] {
				seen[target] = true
				protects[gd.ID] = append(protects[gd.ID], target)
			}
		}
	}

	nv := &netView{byID: map[string]*netBox{}, fbyID: map[string]*netFrame{}, parent: map[string]string{}}

	// A security group that protects nothing yet (a database comes next
	// week) is shown as a box of its own, in its network.
	for _, gd := range g.Nodes {
		if isGuard(gd) && len(protects[gd.ID]) == 0 && !gd.Hidden {
			if v := neighbour(gd.ID, isVNet); v != "" {
				frameOf[gd.ID] = v
				protects[gd.ID] = []string{gd.ID}
			}
		}
	}

	// Public addresses, through a network card or straight on the box.
	public := map[string]bool{}
	for _, e := range g.Edges {
		if e.From == model.InternetID {
			if n := nodeOf(e.To); n != nil && n.Kind == "publicip" {
				for _, nic := range near[n.ID] {
					for _, x := range near[nic] {
						public[x] = true
					}
					public[nic] = true
				}
			} else {
				public[e.To] = true
			}
		}
	}

	// The rules, in words, for the boxes and subnets a group protects; and
	// the arrows, from where traffic may come to what it may reach.
	notes := map[string][]string{}
	sourceName := map[string]string{}
	var actorOrder []string
	actor := func(id, name, friendly, kind string) string {
		if _, ok := sourceName[id]; !ok {
			sourceName[id] = name
			actorOrder = append(actorOrder, id)
			nv.add(&netBox{node: &model.Node{ID: id, Name: name, Friendly: friendly, Kind: kind}, isActor: true})
		}
		return id
	}
	subnetWithAddress := func(cidr string) string {
		for _, n := range g.Nodes {
			if isSubnet(n) && n.Address == cidr && frameOf[n.ID] != "" {
				return n.ID
			}
		}
		return ""
	}
	gateway := map[string]string{} // network -> its internet gateway
	for _, n := range g.Nodes {
		if n.Kind == "globe" && !n.Hidden {
			if v := neighbour(n.ID, isVNet); v != "" {
				gateway[v] = n.ID
			}
		}
	}
	networkOf := func(id string) string {
		for i := 0; i < 4 && id != ""; i++ {
			if n := nodeOf(id); n != nil && isVNet(n) {
				return id
			}
			id = frameOf[id]
		}
		return ""
	}
	for _, e := range g.Edges {
		to := nodeOf(e.To)
		if to == nil || !isGuard(to) || len(protects[e.To]) == 0 {
			continue
		}
		ports := strings.ReplaceAll(strings.ReplaceAll(e.Label, "port ", ""), "ports ", "")
		if ports == "" {
			ports = "traffic"
		}
		var from []string
		who := ""
		switch {
		case e.From == model.InternetID:
			from, who = []string{actor(model.InternetID, "Internet", "anyone, anywhere", "internet")}, "anyone"
		case e.From == model.You:
			from, who = []string{actor(model.You, "Your IP", "only your own address", "identity")}, "your IP"
		case model.IsAddress(e.From):
			cidr := strings.TrimPrefix(e.From, "addr:")
			if s := subnetWithAddress(cidr); s != "" {
				from, who = []string{s}, nodeOf(s).Name
			} else {
				friendly := "these addresses"
				if !strings.ContainsAny(cidr, "0123456789") {
					friendly = "addresses given when deploying" // a parameter or service tag
				}
				from, who = []string{actor(e.From, cidr, friendly, "network")}, cidr
			}
		default:
			src := nodeOf(e.From)
			if src == nil || !isGuard(src) {
				continue
			}
			from, who = protects[e.From], src.Name
			if len(from) == 0 {
				continue
			}
		}
		rule := fmt.Sprintf("%s from %s", ports, who)
		for _, t := range protects[e.To] {
			// In a box: the group's name on a line, then its rules. On a
			// subnet's frame, all on one line.
			header := "▸ " + to.Name
			if t != e.To && !containsLine(notes[t], header) {
				notes[t] = append(notes[t], header)
			}
			notes[t] = append(notes[t], "   "+rule)
			for _, f := range from {
				// From outside, traffic comes in through the network's
				// internet gateway when it has one.
				if gw := gateway[networkOf(t)]; gw != "" && (f == model.InternetID || nv.isActorID(f)) {
					nv.arrow(f, gw, ports, model.Flow, e.Risky)
					nv.arrow(gw, t, ports, model.Flow, e.Risky)
					continue
				}
				nv.arrow(f, t, ports, model.Flow, e.Risky)
			}
		}
	}
	// Straight from the internet to a box, without a security group in
	// between (az vm create's own SSH rule), and lines between the boxes.
	for _, e := range g.Edges {
		from, to := nodeOf(e.From), nodeOf(e.To)
		switch {
		case e.From == model.InternetID && to != nil && member(to) && frameOf[e.To] != "" && e.Label != "":
			nv.arrow(actor(model.InternetID, "Internet", "anyone, anywhere", "internet"), e.To, e.Label, model.Flow, e.Risky)
		case from != nil && to != nil && member(from) && member(to) && (e.Kind == model.Flow || e.Kind == model.Access):
			nv.arrow(e.From, e.To, e.Label, e.Kind, e.Risky)
		}
	}

	// An app's access restriction: traffic from that subnet only.
	for _, e := range g.Edges {
		if strings.Contains(e.Label, "only lets in traffic from") {
			if src := nodeOf(e.To); src != nil {
				notes[e.From] = append(notes[e.From], "only lets in "+src.Name)
				nv.arrow(e.To, e.From, "allowed in", model.Flow, false)
			}
		}
	}
	// An app with VNet integration only sends its own traffic through the
	// subnet; it is still reached on its public address.
	for _, e := range g.Edges {
		if strings.Contains(e.Label, "reaches the network through") && frameOf[e.From] == e.To {
			notes[e.From] = append([]string{"sends its traffic out here"}, notes[e.From]...)
		}
	}

	// The boxes: members in their frames, and what stands outside every
	// network (a storage account, an identity) in a column to the right.
	var outside []*model.Node
	for _, n := range g.Nodes {
		switch {
		case n.Hidden || n.ID == model.InternetID || n.Cloud == "":
		case frameOf[n.ID] != "" && (member(n) || isGuard(n)):
			nv.add(&netBox{node: n, inside: frameOf[n.ID], notes: notes[n.ID], publicIP: public[n.ID]})
		case n.Kind == "globe" && neighbour(n.ID, isVNet) != "":
			nv.add(&netBox{node: n})
		case member(n):
			outside = append(outside, n)
		}
	}
	for _, n := range outside {
		nv.add(&netBox{node: n, inside: "outside"})
	}

	nv.layout(g, vnets, frameOf, notes, actorOrder, gateway)
	return nv, true
}

func (nv *netView) add(b *netBox) {
	if _, ok := nv.byID[b.node.ID]; ok {
		return
	}
	nv.boxes = append(nv.boxes, b)
	nv.byID[b.node.ID] = b
}

func (nv *netView) isActorID(id string) bool {
	b, ok := nv.byID[id]
	return ok && b.isActor
}

// arrow adds a line, once: the same two ends join their labels.
func (nv *netView) arrow(from, to, label, kind string, risky bool) {
	for i, a := range nv.arrows {
		if a.from == from && a.to == to {
			if label != "" && !containsPart(a.label, label) {
				if a.label != "" {
					nv.arrows[i].label += ", "
				}
				nv.arrows[i].label += label
			}
			nv.arrows[i].risky = a.risky || risky
			return
		}
	}
	nv.arrows = append(nv.arrows, netArrow{from: from, to: to, label: label, kind: kind, risky: risky})
}

func containsLine(lines []string, l string) bool {
	for _, x := range lines {
		if x == l {
			return true
		}
	}
	return false
}

func containsPart(list, part string) bool {
	for _, p := range strings.Split(list, ", ") {
		if p == part {
			return true
		}
	}
	return false
}

func boxHeight(b *netBox) int {
	n := len(b.notes)
	if b.publicIP {
		n++
	}
	if n == 0 {
		return nodeH
	}
	return nodeH + n*noteLine + 6
}

// layout places it all: who sends traffic on the left, internet gateways
// next, then each network with its subnets stacked, and what stands
// outside the networks on the right.
func (nv *netView) layout(g *model.Graph, vnets []*model.Node, frameOf map[string]string, notes map[string][]string, actors []string, gateway map[string]string) {
	x := padX
	y0 := padY - 40
	// Column 1: the internet, your IP and other senders.
	y := y0
	for _, id := range actors {
		b := nv.byID[id]
		b.x, b.y, b.h = x, y, nodeH
		y += nodeH + rowGap
	}
	if len(actors) > 0 {
		x += nodeW + netGap
	}
	gwX := x
	if len(gateway) > 0 {
		x += nodeW + netGap
	}

	// Members per frame, in the order of the code.
	in := map[string][]*netBox{}
	for _, b := range nv.boxes {
		if b.inside != "" {
			in[b.inside] = append(in[b.inside], b)
		}
	}
	rowWidth := func(bs []*netBox) int {
		if len(bs) == 0 {
			return 0
		}
		return len(bs)*(nodeW+memberGap) - memberGap
	}
	rowHeight := func(bs []*netBox) int {
		h := 0
		for _, b := range bs {
			b.h = boxHeight(b)
			h = max(h, b.h)
		}
		return h
	}

	maxRight := x
	y = y0
	for _, v := range vnets {
		var subnets []*model.Node
		for _, n := range g.Nodes {
			if n.Kind == "subnet" && !n.Hidden && frameOf[n.ID] == v.ID {
				subnets = append(subnets, n)
			}
		}
		// Public subnets first: that is where traffic comes in.
		sort.SliceStable(subnets, func(i, j int) bool {
			return len(in[subnets[i].ID]) > 0 && len(in[subnets[j].ID]) == 0
		})
		inner := max(nodeW, rowWidth(in[v.ID]))
		for _, s := range subnets {
			inner = max(inner, rowWidth(in[s.ID])+2*subnetPad, nodeW+2*subnetPad)
		}
		vf := &netFrame{id: v.ID, title: frameTitle(v), sub: v.Friendly, class: "vnet " + v.Cloud, x: x, y: y}
		nv.frames = append(nv.frames, vf)
		nv.fbyID[v.ID] = vf
		cy := y + frameHead
		for _, s := range subnets {
			sf := &netFrame{id: s.ID, title: frameTitle(s), class: subnetClass(s), x: x + framePad, y: cy, w: inner, lines: notes[s.ID]}
			extra := len(sf.lines) * noteLine
			members := in[s.ID]
			h := rowHeight(members)
			head := subnetHead
			if len(members) == 0 {
				sf.empty, h, head = true, 14, 30 // nothing comes in, so no lanes
			}
			sf.h = head + extra + h + subnetPad
			mx := sf.x + subnetPad
			for _, b := range members {
				b.x, b.y = mx, cy+subnetHead+extra+subnetPad/2
				mx += nodeW + memberGap
			}
			nv.frames = append(nv.frames, sf)
			nv.fbyID[s.ID] = sf
			nv.parent[s.ID] = v.ID
			cy += sf.h + 14
		}
		if loose := in[v.ID]; len(loose) > 0 {
			h := rowHeight(loose)
			mx := x + framePad
			for _, b := range loose {
				b.x, b.y = mx, cy+4
				mx += nodeW + memberGap
			}
			cy += h + 18
		}
		vf.w = inner + 2*framePad
		vf.h = cy - y + framePad/2
		if gw := gateway[v.ID]; gw != "" {
			b := nv.byID[gw]
			b.x, b.y, b.h = gwX, y+frameHead, nodeH
		}
		maxRight = max(maxRight, x+vf.w)
		y += vf.h + 40
	}
	bottom := y

	// Outside every network, on the right.
	// They are laid out as a flow of their own, so a group that may read a
	// storage account stands to its left, not in a long column with it.
	if out := in["outside"]; len(out) > 0 {
		sub := &model.Graph{}
		isOut := map[string]bool{}
		for _, b := range out {
			sub.Nodes = append(sub.Nodes, b.node)
			isOut[b.node.ID] = true
		}
		for _, a := range nv.arrows {
			if isOut[a.from] && isOut[a.to] {
				sub.Edges = append(sub.Edges, model.Edge{From: a.from, To: a.to, Kind: a.kind})
			}
		}
		layer := flowLayers(sub.Nodes, sub.Edges)
		cols := map[int][]*netBox{}
		var keys []int
		for _, b := range out {
			k := layer[b.node.ID]
			if k == loneLayer {
				k = 0 // nothing outside points at it: next to the network
			}
			if _, ok := cols[k]; !ok {
				keys = append(keys, k)
			}
			cols[k] = append(cols[k], b)
		}
		sort.Ints(keys)
		ox := maxRight + netGap
		for _, k := range keys {
			oy := y0
			for _, b := range cols[k] {
				b.h = boxHeight(b)
				b.x, b.y = ox, oy
				oy += b.h + rowGap
			}
			bottom = max(bottom, oy)
			maxRight = ox + nodeW
			ox += nodeW + netGap
		}
	}
	for _, b := range nv.boxes {
		if b.inside != "" && b.inside != "outside" {
			nv.parent[b.node.ID] = b.inside
		}
	}
	nv.w = maxRight + padX
	nv.h = max(bottom, y) + padX
}

func frameTitle(n *model.Node) string {
	if strings.Contains(n.Address, "/") {
		return n.Name + "  " + n.Address
	}
	return n.Name
}

func subnetClass(n *model.Node) string {
	cls := "subnet " + n.Cloud
	if n.Cloud == "aws" {
		if strings.Contains(strings.ToLower(n.Name), "public") {
			cls += " public"
		} else {
			cls += " private"
		}
	}
	return cls
}

// rect is where a box or frame is.
func (nv *netView) rect(id string) (x, y, w, h int, ok bool) {
	if b, found := nv.byID[id]; found {
		return b.x, b.y, nodeW, b.h, true
	}
	if f, found := nv.fbyID[id]; found {
		return f.x, f.y, f.w, f.h, true
	}
	return 0, 0, 0, 0, false
}

// connector draws a soft curve between two rectangles, leaving the side
// that faces the other one.
func connector(ax, ay, aw, ah, bx, by, bw, bh int) (d string, lx, ly int) {
	acx, acy := ax+aw/2, ay+ah/2
	bcx, bcy := bx+bw/2, by+bh/2
	switch {
	case bx >= ax+aw+20: // to the right
		x1, y1, x2, y2 := ax+aw, acy, bx, min(max(acy, by+16), by+bh-16)
		if bh > 2*nodeH { // a frame: arrive by its name
			y2 = by + 18
		}
		c := (x2 - x1) / 2
		return fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, x1+c, y1, x2-c, y2, x2, y2), x2 - 12, y2 - 6
	case bx+bw+20 <= ax: // to the left
		x1, y1, x2, y2 := ax, acy, bx+bw, bcy
		c := (x1 - x2) / 2
		return fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, x1-c, y1, x2+c, y2, x2, y2), x2 + 12, y2 - 6
	case by >= ay+ah: // below
		x1, y1, x2, y2 := acx, ay+ah, bcx, by
		c := (y2 - y1) / 2
		return fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, x1, y1+c, x2, y2-c, x2, y2), (x1+x2)/2 + 6, (y1+y2)/2 + 4
	default: // above
		x1, y1, x2, y2 := acx, ay, bcx, by+bh
		c := (y1 - y2) / 2
		return fmt.Sprintf("M%d %d C%d %d %d %d %d %d", x1, y1, x1, y1-c, x2, y2+c, x2, y2), (x1+x2)/2 + 6, (y1+y2)/2 + 4
	}
}

// networkPicture fills a project's picture from a network view.
func networkPicture(p *project, g *model.Graph, nv *netView, opt Options) {
	p.W, p.H, p.Flow, p.Network = nv.w, nv.h, true, true
	var used []string
	for _, f := range nv.frames {
		sf := svgFrame{X: f.x, Y: f.y, W: f.w, H: f.h, Title: clip(f.title, 60), Sub: clip(f.sub, 110), Class: f.class}
		top := 30
		if f.sub != "" {
			top += noteLine
		}
		for i, l := range f.lines {
			sf.Lines = append(sf.Lines, svgText{X: f.x + 12, Y: f.y + top + i*noteLine, Text: clip(l, f.w/6)})
		}
		if f.empty {
			sf.Empty = "nothing in it yet"
		}
		p.Frames = append(p.Frames, sf)
	}
	for _, b := range nv.boxes {
		sn := boxFor(g, b.node, b.x, b.y, b.h, opt)
		sn.id = b.node.ID
		if b.isActor {
			sn.Href, sn.Code = "", ""
		}
		lines := b.notes
		if b.publicIP {
			lines = append([]string{"has a public IP address"}, lines...)
		}
		for i, n := range lines {
			sn.Notes = append(sn.Notes, svgText{X: b.x + 10, Y: b.y + nodeH + 4 + i*noteLine, Text: clip(n, 30)})
			sn.Tooltip += "\n" + n
		}
		used = append(used, sn.Official)
		p.Nodes = append(p.Nodes, sn)
	}
	lanes := map[string]int{}
	for _, a := range nv.arrows {
		ax, ay, aw, ah, ok1 := nv.rect(a.from)
		bx, by, bw, bh, ok2 := nv.rect(a.to)
		if !ok1 || !ok2 {
			continue
		}
		// Several arrows into one frame arrive one under the other.
		if _, isFrame := nv.fbyID[a.to]; isFrame {
			k := lanes["in:"+a.to]
			lanes["in:"+a.to]++
			by += 14 * k
		}
		d, lx, ly := connector(ax, ay, aw, ah, bx, by, bw, bh)
		se := svgEdge{D: d, Risky: a.risky, Kind: a.kind, Label: a.label, LX: lx, LY: ly, Anchor: "end", from: a.from, to: a.to}
		if bx < ax+aw+20 {
			se.Anchor = ""
		}
		// Traffic from outside comes down into a box in a subnet from
		// above, so it is clear which box it reaches, also when other
		// boxes stand in the way.
		if src, dst := nv.byID[a.from], nv.byID[a.to]; src != nil && dst != nil && src.inside == "" && dst.inside != "" && dst.inside != "outside" && bx >= ax+aw+20 {
			// Along a lane of its own under the subnet's name, then down.
			k := lanes[dst.inside]
			lanes[dst.inside]++
			x1, y1 := ax+aw, ay+ah/2
			x2, y2 := bx+bw/2, by
			lane := y2 - 10 - 7*k
			se.D = fmt.Sprintf("M%d %d C%d %d %d %d %d %d L%d %d C%d %d %d %d %d %d",
				x1, y1, x1+60, y1, x1+40, lane, x1+100, lane, x2-24, lane, x2, lane, x2, lane, x2, y2)
			se.LX, se.LY, se.Anchor = x2-28, lane-4, "end"
		}
		if a.label != "" {
			se.Lines = wrapLabel(a.label, 24)
			se.LY -= 12 * (len(se.Lines) - 1)
		}
		p.Edges = append(p.Edges, se)
	}
	p.Symbols = iconSymbols(used)
}

// drawioNetwork writes a network picture as draw.io cells: the networks
// and subnets as frames behind the boxes, the rules under each box's name,
// and the traffic as arrows.
func drawioNetwork(b *strings.Builder, g *model.Graph, nv *netView, root string) {
	ids := map[string]string{}
	for i, f := range nv.frames {
		id := fmt.Sprintf("f%d", i+1)
		ids[f.id] = id
		stroke, dash := "#0078d4", "0"
		switch {
		case strings.Contains(f.class, "vnet aws"):
			stroke = "#8c4fff"
		case strings.Contains(f.class, "public"):
			stroke, dash = "#7aa116", "1"
		case strings.Contains(f.class, "private"):
			stroke, dash = "#00a4a6", "1"
		case strings.Contains(f.class, "subnet"):
			stroke, dash = "#50a0e0", "1"
		}
		value := f.title
		if f.sub != "" {
			value += "\n" + f.sub
		}
		for _, l := range f.lines {
			value += "\n" + strings.TrimSpace(l)
		}
		if f.empty {
			value += "\n(nothing in it yet)"
		}
		fmt.Fprintf(b, `        <mxCell id="%s" value="%s" style="rounded=1;arcSize=4;whiteSpace=wrap;html=0;fillColor=none;strokeColor=%s;dashed=%s;strokeWidth=1.5;verticalAlign=top;align=left;spacingLeft=10;spacingTop=4;fontStyle=1;fontSize=11;" vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>`+"\n",
			id, xmlText(value), stroke, dash, f.x, f.y, f.w, f.h)
	}
	for i, bx := range nv.boxes {
		n := bx.node
		id := fmt.Sprintf("n%d", i+1)
		ids[n.ID] = id
		fill, stroke := drawioColors(n.Category)
		width := 1.5
		if sev, ok := g.Worst(n.ID); ok {
			switch sev {
			case model.High:
				stroke, width = "#d1242f", 3
			case model.Medium:
				stroke, width = "#b35900", 2.5
			}
		}
		value := n.Name
		if n.Friendly != "" {
			value += "\n" + n.Friendly
		}
		if bx.publicIP {
			value += "\nhas a public IP address"
		}
		for _, l := range bx.notes {
			value += "\n" + strings.TrimSpace(l)
		}
		tooltip := ""
		if n.File != "" {
			tooltip = fmt.Sprintf("%s:%d", relTo(root, n.File), n.Line)
		}
		fmt.Fprintf(b, `        <mxCell id="%s" value="%s" tooltip="%s" style="rounded=1;arcSize=12;whiteSpace=wrap;html=0;fillColor=%s;strokeColor=%s;strokeWidth=%.1f;fontSize=11;align=left;verticalAlign=top;spacingLeft=10;spacingTop=6;" vertex="1" parent="1"><mxGeometry x="%d" y="%d" width="%d" height="%d" as="geometry"/></mxCell>`+"\n",
			id, xmlText(value), xmlText(tooltip), fill, stroke, width, bx.x, bx.y, nodeW, bx.h)
	}
	for i, a := range nv.arrows {
		from, to := ids[a.from], ids[a.to]
		if from == "" || to == "" {
			continue
		}
		style := "edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;strokeColor=#4a6a8f;strokeWidth=1.5;endArrow=block;endFill=1;fontSize=10;"
		switch {
		case a.risky:
			style = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;strokeColor=#d1242f;strokeWidth=2;dashed=1;endArrow=block;endFill=1;fontColor=#d1242f;fontSize=10;"
		case a.kind == model.Access:
			style = "edgeStyle=orthogonalEdgeStyle;rounded=1;html=0;strokeColor=#8250df;dashed=1;endArrow=block;endFill=1;fontColor=#8250df;fontSize=10;"
		}
		fmt.Fprintf(b, `        <mxCell id="e%d" value="%s" style="%s" edge="1" parent="1" source="%s" target="%s"><mxGeometry relative="1" as="geometry"/></mxCell>`+"\n",
			i+1, xmlText(a.label), style, from, to)
	}
}

// mermaidNetwork writes a network picture as Mermaid: each network a
// group, each subnet a group inside it, the rules in the boxes, and the
// traffic as arrows.
func mermaidNetwork(b *strings.Builder, g *model.Graph, nv *netView) {
	ids := map[string]string{}
	n := 0
	box := func(bx *netBox, indent string) {
		n++
		id := fmt.Sprintf("n%d", n)
		ids[bx.node.ID] = id
		text := label(bx.node.Name)
		if bx.node.Friendly != "" {
			text += "<br/><small>" + label(bx.node.Friendly) + "</small>"
		}
		if bx.publicIP {
			text += "<br/><small>has a public IP address</small>"
		}
		for _, l := range bx.notes {
			text += "<br/><small>" + label(strings.TrimSpace(l)) + "</small>"
		}
		fmt.Fprintf(b, "%s%s[\"%s\"]\n", indent, id, text)
		if sev, ok := g.Worst(bx.node.ID); ok {
			fmt.Fprintf(b, "%sclass %s %s\n", indent, id, sev)
		}
	}
	in := map[string][]*netBox{}
	for _, bx := range nv.boxes {
		in[bx.inside] = append(in[bx.inside], bx)
	}
	for _, bx := range in[""] {
		box(bx, "  ")
	}
	f := 0
	for _, fr := range nv.frames {
		if nv.parent[fr.id] != "" {
			continue // a subnet, written inside its network
		}
		f++
		fid := fmt.Sprintf("f%d", f)
		ids[fr.id] = fid
		fmt.Fprintf(b, "  subgraph %s[\"%s\"]\n", fid, label(fr.title))
		for _, sub := range nv.frames {
			if nv.parent[sub.id] != fr.id {
				continue
			}
			f++
			sid := fmt.Sprintf("f%d", f)
			ids[sub.id] = sid
			fmt.Fprintf(b, "    subgraph %s[\"%s\"]\n", sid, label(sub.title))
			if len(sub.lines) > 0 {
				// The subnet's rules, as a note inside it.
				var rules []string
				for _, l := range sub.lines {
					rules = append(rules, label(strings.TrimSpace(l)))
				}
				f++
				fmt.Fprintf(b, "      f%d[\"<small>%s</small>\"]\n      class f%d rules\n", f, strings.Join(rules, "<br/>"), f)
			}
			if len(in[sub.id]) == 0 {
				f++
				fmt.Fprintf(b, "      f%d[\"nothing in it yet\"]\n", f)
			}
			for _, bx := range in[sub.id] {
				box(bx, "      ")
			}
			b.WriteString("    end\n")
		}
		for _, bx := range in[fr.id] {
			box(bx, "    ")
		}
		b.WriteString("  end\n")
	}
	for _, bx := range in["outside"] {
		box(bx, "  ")
	}
	edge := 0
	var risky, access []int
	for _, a := range nv.arrows {
		from, to := ids[a.from], ids[a.to]
		if from == "" || to == "" {
			continue
		}
		arrow := "-->"
		if a.risky {
			arrow = "-.->"
			risky = append(risky, edge)
		} else if a.kind == model.Access {
			arrow = "-.->"
			access = append(access, edge)
		}
		if a.label != "" {
			fmt.Fprintf(b, "  %s %s|\"%s\"| %s\n", from, arrow, label(a.label), to)
		} else {
			fmt.Fprintf(b, "  %s %s %s\n", from, arrow, to)
		}
		edge++
	}
	b.WriteString("  classDef high stroke:#d1242f,stroke-width:3px\n")
	b.WriteString("  classDef medium stroke:#b35900,stroke-width:2px\n")
	b.WriteString("  classDef low stroke:#2f6fb3\n")
	b.WriteString("  classDef rules fill:none,stroke-dasharray:3 3\n")
	for _, i := range risky {
		fmt.Fprintf(b, "  linkStyle %d stroke:#d1242f,stroke-width:2px\n", i)
	}
	for _, i := range access {
		fmt.Fprintf(b, "  linkStyle %d stroke:#8250df,color:#8250df\n", i)
	}
}
