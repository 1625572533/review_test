package output

import (
	"fmt"
	"sort"
	"strings"

	"review_test/internal/model"
)

func Text(assets []model.Asset) string {
	var b strings.Builder
	b.WriteString("services:\n")

	ptrSet := map[string]struct{}{}
	sort.Slice(assets, func(i, j int) bool {
		return assets[i].IP < assets[j].IP
	})

	for _, asset := range assets {
		for _, ptr := range asset.PTRs {
			ptrSet[ptr] = struct{}{}
		}
		services := append([]model.Service(nil), asset.Services...)
		sort.Slice(services, func(i, j int) bool {
			if services[i].Port != services[j].Port {
				return services[i].Port < services[j].Port
			}
			if services[i].Proto != services[j].Proto {
				return services[i].Proto < services[j].Proto
			}
			return services[i].Type < services[j].Type
		})
		for _, service := range services {
			proto := service.Proto
			if proto == "" {
				proto = "tcp"
			}
			fmt.Fprintf(&b, "%d/%s %s: %s\n", service.Port, proto, service.Type, service.Banner)
		}
	}

	var ptrs []string
	for ptr := range ptrSet {
		ptrs = append(ptrs, ptr)
	}
	sort.Strings(ptrs)

	b.WriteString("answers:\n")
	b.WriteString("PTR:")
	if len(ptrs) > 0 {
		b.WriteByte(' ')
		b.WriteString(strings.Join(ptrs, " "))
	}
	b.WriteByte('\n')
	return b.String()
}
