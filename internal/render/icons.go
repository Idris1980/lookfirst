package render

import "html/template"

// icons are drawn in a 24x24 box with currentColor strokes. They are our
// own simple shapes, so the report needs no external files and no licence.
var icons = map[string]template.HTML{
	"internet":     `<path d="M7 18h10a4 4 0 0 0 0-8 6 6 0 0 0-11.3 1.5A3.5 3.5 0 0 0 7 18z"/>`,
	"vm":           `<rect x="3" y="4" width="18" height="12" rx="2"/><path d="M8 20h8M12 16v4"/>`,
	"network":      `<circle cx="5" cy="12" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="19" cy="18" r="2"/><path d="M7 11l10-4M7 13l10 4"/>`,
	"subnet":       `<rect x="3" y="3" width="18" height="18" rx="2"/><path d="M3 12h18M12 3v18"/>`,
	"nic":          `<rect x="3" y="7" width="18" height="10" rx="1"/><path d="M7 17v3M11 17v3M15 17v3"/><rect x="7" y="10" width="4" height="4"/>`,
	"publicip":     `<circle cx="12" cy="12" r="9"/><ellipse cx="12" cy="12" rx="4" ry="9"/><path d="M3 12h18"/>`,
	"loadbalancer": `<circle cx="12" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="M12 7v10M11 7l-5 10M13 7l5 10"/>`,
	"shield":       `<path d="M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6z"/>`,
	"firewall":     `<rect x="3" y="4" width="18" height="16" rx="1"/><path d="M3 9.3h18M3 14.7h18M9 4v5.3M15 4v5.3M6 9.3v5.4M12 9.3v5.4M18 9.3v5.4M9 14.7V20M15 14.7V20"/>`,
	"key":          `<circle cx="8" cy="12" r="4"/><path d="M12 12h9M18 12v3M21 12v2"/>`,
	"identity":     `<circle cx="12" cy="8" r="4"/><path d="M4 21c0-4 4-6 8-6s8 2 8 6"/>`,
	"kubernetes":   `<path d="M12 2l8.5 4.5 2 9.5-6 6.5h-9l-6-6.5 2-9.5z"/><circle cx="12" cy="12" r="3"/>`,
	"container":    `<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M12 12l8-4.5M12 12v9M12 12L4 7.5"/>`,
	"plan":         `<path d="M12 3l9 5-9 5-9-5z"/><path d="M3 13l9 5 9-5"/>`,
	"webapp":       `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M3 9h18"/><circle cx="6" cy="6.5" r=".5"/><circle cx="8.5" cy="6.5" r=".5"/>`,
	"function":     `<path d="M13 2L4 14h7l-1 8 9-12h-7z"/>`,
	"storage":      `<rect x="4" y="4" width="16" height="6" rx="1"/><rect x="4" y="14" width="16" height="6" rx="1"/><path d="M8 7h.01M8 17h.01"/>`,
	"database":     `<ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>`,
	"code":         `<path d="M8 7l-5 5 5 5M16 7l5 5-5 5M14 4l-4 16"/>`,
	"globe":        `<circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3c2.5 2.5 3.5 5.5 3.5 9s-1 6.5-3.5 9c-2.5-2.5-3.5-5.5-3.5-9s1-6.5 3.5-9z"/>`,
	"folder":       `<path d="M3 6.5A1.5 1.5 0 0 1 4.5 5H9l2 2.5h8.5A1.5 1.5 0 0 1 21 9v9.5a1.5 1.5 0 0 1-1.5 1.5h-15A1.5 1.5 0 0 1 3 18.5z"/>`,
	"terminal":     `<rect x="3" y="4" width="18" height="16" rx="2"/><path d="M7 9l3 3-3 3M12 15h5"/>`,
	"package":      `<path d="M12 3l8 4.5v9L12 21l-8-4.5v-9z"/><path d="M4 7.5l8 4.5 8-4.5M12 12v9M8 5.3l8 4.5"/>`,
	"monitor":      `<path d="M3 12h4l2-6 4 12 2-6h6"/>`,
	"dns":          `<circle cx="12" cy="12" r="9"/><path d="M8 9h8M8 12h8M8 15h5"/>`,
	"relay":        `<circle cx="5" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><path d="M7 12h3M14 12h3M10 9l2 3-2 3M14 9l-2 3 2 3"/>`,
	"generic":      `<rect x="4" y="4" width="16" height="16" rx="3"/>`,
}

func icon(kind string) template.HTML {
	if i, ok := icons[kind]; ok {
		return i
	}
	return icons["generic"]
}
