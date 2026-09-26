package engine

import "slices"

// matches 判断策略条件是否全部满足（未设置的条件视为满足）。
func (p *Policy) matches(attrs *UserAttrs, authMethod string) bool {
	if p.Role != "" && p.Role != attrs.Role {
		return false
	}
	if p.Department != "" && p.Department != attrs.Department {
		return false
	}
	if p.DeviceType != "" && p.DeviceType != attrs.DeviceType {
		return false
	}
	if len(p.AuthMethods) > 0 && !slices.Contains(p.AuthMethods, authMethod) {
		return false
	}
	if p.MinClearance != 0 && attrs.Clearance < p.MinClearance {
		return false
	}
	if p.MaxClearance != 0 && attrs.Clearance > p.MaxClearance {
		return false
	}
	return true
}

// better 报告 a 是否比 b 更优：优先级高者胜；并列时 ID 字节序小者胜。
func better(a, b *Policy) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	return a.ID < b.ID
}

// evaluate 在策略快照上对给定属性与认证方式求值。无匹配时返回隔离决策。
// 调用方需保证 policies 在调用期间不被修改（持有读锁）。
func evaluate(policies map[string]*Policy, attrs *UserAttrs, authMethod string) Decision {
	var best *Policy
	for _, p := range policies {
		if !p.matches(attrs, authMethod) {
			continue
		}
		if best == nil || better(p, best) {
			best = p
		}
	}
	if best == nil {
		return Quarantine
	}
	ports := make([]int, len(best.Ports))
	copy(ports, best.Ports)
	return Decision{VLAN: best.VLAN, Ports: ports}
}

// equalDecision 比较两个决策是否相同。
func equalDecision(a, b Decision) bool {
	return a.VLAN == b.VLAN && slices.Equal(a.Ports, b.Ports)
}
