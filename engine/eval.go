package engine

// evalDecision 用给定的有序策略列表（已按优先级降序、ID 升序排好）、
// 用户属性和会话的 authMethod 求值，返回第一条匹配策略的结果；
// 全部不匹配时返回隔离网段决策。
func evalDecision(sorted []*Policy, attrs UserAttrs, authMethod string) Decision {
	for _, p := range sorted {
		if matches(p, attrs, authMethod) {
			ports := make([]uint16, len(p.Ports))
			copy(ports, p.Ports)
			return Decision{VLAN: p.VLAN, Ports: ports}
		}
	}
	return Quarantine
}

// matches 判断策略条件是否全部满足；未设置的条件视为满足。
func matches(p *Policy, attrs UserAttrs, authMethod string) bool {
	c := &p.Cond
	if c.Role != nil && *c.Role != attrs.Role {
		return false
	}
	if c.Department != nil && *c.Department != attrs.Department {
		return false
	}
	if c.DeviceType != nil && *c.DeviceType != attrs.DeviceType {
		return false
	}
	if len(c.AuthMethods) > 0 {
		found := false
		for _, m := range c.AuthMethods {
			if m == authMethod {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if c.Clearance != nil {
		if attrs.Clearance < c.Clearance.Min || attrs.Clearance > c.Clearance.Max {
			return false
		}
	}
	return true
}

// equalDecision 判断两个决策是否相同。
func equalDecision(a, b Decision) bool {
	if a.VLAN != b.VLAN || len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	return true
}
