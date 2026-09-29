// Package custom adapts the controller's fixed lifecycle operations (probe,
// inventory, load, drain, unload) onto an actual process, using a validated
// custom manifest and command-plan contract. It never interprets a shell, never
// inherits ambient environment, never accepts a controller credential or network
// endpoint, and always fails closed.
//
// The plan is the boundary: it is parsed and validated against a strict structural
// grammar (mirroring the TypeScript manifest/plan units), then deeply copied and
// frozen so no caller-owned reference stays mutable. Execution rechecks local
// authorization immediately before every spawn, bounds stdout/stderr bytes,
// honours context cancellation and a per-plan timeout, redacts every failure to a
// stable machine-readable code (never an executable, argv, env value, endpoint,
// credential, OS error, or hostile output), and post-verifies the returned
// observation against the runtime contract before the controller is allowed to
// trust it. Every result handed back is detached and immutable.
package custom

import (
	"errors"
	"path"
	"regexp"
	"strings"
)

// ErrCustomPlan is the single stable machine code emitted by the plan matcher.
// It is never an echo of untrusted input and is never a thrown exception.
var ErrCustomPlan = errors.New("ERR_CUSTOM_COMMAND_PLAN")

// Bounds folded into the plan grammar (the manifest supplies these).
const (
	maxTimeoutMs        = 60_000
	maxOutputBytes      = 1_048_576
	maxExecutableLength = 200
	maxSlots            = 8
	maxEnvEntries       = 8
	maxArgvEntries      = 8
	maxArgvEntryLength  = 100
	maxEnvNameLength    = 32
	maxEnvValueLength   = 100

	slotString  = "string"
	slotInteger = "integer"
	slotBoolean = "boolean"

	flavorPosix = "posix"
	flavorWin32 = "win32"
)

// PathFlavor selects the path grammar applied to an executable.
type PathFlavor string

// CustomActionTemplate mirrors the TypeScript manifest action template: an exact
// executable plus validated argv, env, and bounded limits. It carries no shell,
// URL, address, or credential surface.
type CustomActionTemplate struct {
	ActionID       string
	Executable     string
	Argv           []string
	Env            map[string]string
	TimeoutMs      int
	MaxOutputBytes int
}

// CommandPlaceSlot is one declared bindable argv slot.
type CommandPlaceSlot struct {
	SlotID string
	Kind   string
	Length int
	Min    int
	Max    int
	HasMin bool
	HasMax bool
}

// CustomActionBinding mirrors the TypeScript binding: it names the provider and
// caller, the allowlisted executable roots and env keys, the declared slots, and
// the concrete values bound to each slot.
type CustomActionBinding struct {
	ProviderID     string
	CallerID       string
	AllowedRoots   []string
	AllowedEnvKeys []string
	Slots          []CommandPlaceSlot
	ValueBinds     map[string]any
}

// CommandPlanGlobalCaps mirrors the TypeScript global caps applied to a plan.
type CommandPlanGlobalCaps struct {
	MaxTimeoutMs        int
	MaxOutputBytes      int
	MaxExecutableLength int
	MaxSlots            int
	MaxEnvEntries       int
}

// CustomCommandPlan is the fully validated, detached, frozen plan produced by
// Plan. All fields are exported for structural ergonomics but every value is a
// private copy owned by this plan; the zero value is invalid.
type CustomCommandPlan struct {
	providerID     string
	callerID       string
	actionID       string
	flavor         PathFlavor
	executable     string
	argv           []string
	env            map[string]string
	timeoutMs      int
	maxOutputBytes int
}

// Accessors return private copies, so the returned plan is immutable and no
// caller-owned reference stays reachable.
func (p *CustomCommandPlan) ProviderID() string { return p.providerID }
func (p *CustomCommandPlan) CallerID() string   { return p.callerID }
func (p *CustomCommandPlan) ActionID() string   { return p.actionID }
func (p *CustomCommandPlan) Flavor() PathFlavor { return p.flavor }
func (p *CustomCommandPlan) Executable() string { return p.executable }
func (p *CustomCommandPlan) Argv() []string {
	if p.argv == nil {
		return nil
	}
	cp := make([]string, len(p.argv))
	copy(cp, p.argv)
	return cp
}
func (p *CustomCommandPlan) Env() map[string]string {
	if p.env == nil {
		return nil
	}
	cp := make(map[string]string, len(p.env))
	for k, v := range p.env {
		cp[k] = v
	}
	return cp
}
func (p *CustomCommandPlan) TimeoutMs() int      { return p.timeoutMs }
func (p *CustomCommandPlan) MaxOutputBytes() int { return p.maxOutputBytes }

// Plan validates a manifest action template plus its binding and global caps
// against a path flavor and returns a fully detached, frozen plan, or the single
// stable machine code ErrCustomPlan on any structural deviation or invalid limit.
// It is non-throwing: hostile or exotic inputs fail closed without ever invoking
// a getter or returning untrusted material.
func Plan(template CustomActionTemplate, binding CustomActionBinding, caps CommandPlanGlobalCaps, flavor PathFlavor) (*CustomCommandPlan, error) {
	if flavor != flavorPosix && flavor != flavorWin32 {
		return nil, ErrCustomPlan
	}
	if !capsValid(caps) {
		return nil, ErrCustomPlan
	}
	if !providerIDOk(binding.ProviderID) || !providerIDOk(binding.CallerID) {
		return nil, ErrCustomPlan
	}
	if !identifier(template.ActionID) {
		return nil, ErrCustomPlan
	}
	if !capsOK("timeout", template.TimeoutMs, caps.MaxTimeoutMs) {
		return nil, ErrCustomPlan
	}
	if !capsOK("output", template.MaxOutputBytes, caps.MaxOutputBytes) {
		return nil, ErrCustomPlan
	}
	executable := canonicalPath(template.Executable, flavor, caps.MaxExecutableLength)
	if executable == "" {
		return nil, ErrCustomPlan
	}
	roots, ok := allowedRoots(binding.AllowedRoots, caps.MaxExecutableLength, flavor)
	if !ok {
		return nil, ErrCustomPlan
	}
	if !containsAny(roots, executable, flavor) {
		return nil, ErrCustomPlan
	}
	envAllow, ok := allowedEnvKeys(binding.AllowedEnvKeys, caps.MaxEnvEntries)
	if !ok {
		return nil, ErrCustomPlan
	}
	argv, ok := bindArgv(template.Argv, binding, caps)
	if !ok {
		return nil, ErrCustomPlan
	}
	env, ok := bindEnv(template.Env, envAllow)
	if !ok {
		return nil, ErrCustomPlan
	}
	return &CustomCommandPlan{
		providerID:     binding.ProviderID,
		callerID:       binding.CallerID,
		actionID:       template.ActionID,
		flavor:         flavor,
		executable:     executable,
		argv:           argv,
		env:            env,
		timeoutMs:      template.TimeoutMs,
		maxOutputBytes: template.MaxOutputBytes,
	}, nil
}

// --- helpers ----------------------------------------------------------------

func capsValid(caps CommandPlanGlobalCaps) bool {
	return caps.MaxTimeoutMs >= 1 && caps.MaxTimeoutMs <= maxTimeoutMs &&
		caps.MaxOutputBytes >= 1 && caps.MaxOutputBytes <= maxOutputBytes &&
		caps.MaxExecutableLength >= 1 && caps.MaxExecutableLength <= maxExecutableLength &&
		caps.MaxSlots >= 1 && caps.MaxSlots <= maxSlots &&
		caps.MaxEnvEntries >= 1 && caps.MaxEnvEntries <= maxEnvEntries
}

func capsOK(name string, value, cap int) bool {
	if name == "timeout" {
		return value >= 1 && value <= maxTimeoutMs && value <= cap
	}
	return value >= 1 && value <= maxOutputBytes && value <= cap
}

var (
	providerIDRegex = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	idRegex         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	phRegex         = regexp.MustCompile(`^--ph-([A-Za-z0-9][A-Za-z0-9._:-]{0,127})$`)
	envKeyRegex     = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,31}$`)
	controlBytes    = regexp.MustCompile(`[\x00-\x1f\x7f]`)
	shellChars      = regexp.MustCompile(`[;|&` + "`" + `<>(){}\[\]'"$]`)
	// Sensitive public values: credentials, tokens, URLs/endpoints, LAN addresses.
	sensitive = regexp.MustCompile(`(?i)(?:pass(?:word|wd)?|passwd|pwd|secret|token|api[-_]?key|access[-_]?key|private[-_]?key|authorization|bearer|credential|login|username|://|localhost|\.local|127\.|0\.0\.0\.0|192\.168\.|10\.\d+\.|169\.254\.|172\.(?:1[6-9]|2\d|3[01])\.|::1|fe80::|fd:)`)
)

func providerIDOk(raw string) bool { return identifier(raw) && !sensitive.MatchString(raw) }

func identifier(raw string) bool {
	if len(raw) < 1 || len(raw) > 128 {
		return false
	}
	return idRegex.MatchString(raw) && !sensitive.MatchString(raw)
}

// safeString returns raw when it is a safe bounded string (no control bytes, no
// shell metacharacters, no sensitive public value), else "".
func safeString(raw string, max int, allowSpace bool) string {
	if len(raw) < 1 || len(raw) > max || controlBytes.MatchString(raw) || shellChars.MatchString(raw) || sensitive.MatchString(raw) {
		return ""
	}
	if !allowSpace && containsWhitespace(raw) {
		return ""
	}
	return raw
}

func containsWhitespace(s string) bool {
	for _, r := range s {
		if r == ' ' || r == '\t' || r == '\n' || r == '\r' {
			return true
		}
	}
	return false
}

func contains(haystack string, needle rune) bool {
	for _, r := range haystack {
		if r == needle {
			return true
		}
	}
	return false
}

func allowedRoots(raw []string, maxExec int, flavor PathFlavor) ([]string, bool) {
	if len(raw) < 1 || len(raw) > maxSlots {
		return nil, false
	}
	roots := make([]string, 0, len(raw))
	for _, entry := range raw {
		root := canonicalPath(entry, flavor, maxExec, true)
		if root == "" {
			return nil, false
		}
		for _, prior := range roots {
			if prior == root {
				return nil, false
			}
		}
		roots = append(roots, root)
	}
	return roots, true
}

func allowedEnvKeys(raw []string, maxEnv int) (map[string]struct{}, bool) {
	// An empty allowlist is permitted: it simply maps to no allowed keys (any env
	// entry in the template will then be rejected). Only overflow fails.
	if len(raw) > maxEnv {
		return nil, false
	}
	set := make(map[string]struct{}, len(raw))
	for _, key := range raw {
		if !envKeyOk(key) {
			return nil, false
		}
		if _, exists := set[key]; exists {
			return nil, false
		}
		set[key] = struct{}{}
	}
	return set, true
}

func envKeyOk(key string) bool {
	if len(key) < 1 || len(key) > maxEnvNameLength {
		return false
	}
	return envKeyRegex.MatchString(key)
}

func declaredSlots(raw []CommandPlaceSlot, maxSlots int) (map[string]CommandPlaceSlot, bool) {
	if len(raw) > maxSlots {
		return nil, false
	}
	out := make(map[string]CommandPlaceSlot)
	for _, slot := range raw {
		if !identifier(slot.SlotID) {
			return nil, false
		}
		if slot.Kind != slotString && slot.Kind != slotInteger && slot.Kind != slotBoolean {
			return nil, false
		}
		if slot.Length < 1 || slot.Length > maxArgvEntryLength {
			return nil, false
		}
		if slot.Kind != slotInteger && (slot.HasMin || slot.HasMax) {
			return nil, false
		}
		if slot.Kind == slotInteger && slot.HasMin && slot.HasMax && slot.Min > slot.Max {
			return nil, false
		}
		if _, exists := out[slot.SlotID]; exists {
			return nil, false
		}
		out[slot.SlotID] = slot
	}
	return out, true
}

func bindArgv(raw []string, binding CustomActionBinding, caps CommandPlanGlobalCaps) ([]string, bool) {
	if len(raw) < 1 || len(raw) > maxArgvEntries {
		return nil, false
	}
	slots, ok := declaredSlots(binding.Slots, caps.MaxSlots)
	if !ok {
		return nil, false
	}
	if len(binding.ValueBinds) != len(slots) {
		return nil, false
	}
	argv := make([]string, 0, len(raw))
	used := make(map[string]bool)
	for _, entry := range raw {
		if len(entry) < 1 || len(entry) > maxArgvEntryLength || controlBytes.MatchString(entry) || shellChars.MatchString(entry) || sensitive.MatchString(entry) {
			return nil, false
		}
		match := phRegex.FindStringSubmatch(entry)
		if match == nil {
			argv = append(argv, entry)
			continue
		}
		slotID := match[1]
		slot, slotOk := slots[slotID]
		descriptor, bindOk := binding.ValueBinds[slotID]
		if !slotOk || !bindOk || used[slotID] {
			return nil, false
		}
		value, valueOk := bindValue(descriptor, slot)
		if !valueOk {
			return nil, false
		}
		used[slotID] = true
		argv = append(argv, value)
	}
	if len(used) != len(slots) {
		return nil, false
	}
	return argv, true
}

func bindEnv(env map[string]string, allow map[string]struct{}) (map[string]string, bool) {
	// An empty env is permitted: nothing to validate.
	if len(env) == 0 {
		return map[string]string{}, true
	}
	out := make(map[string]string)
	for key, value := range env {
		if _, permitted := allow[key]; !permitted {
			return nil, false
		}
		if !envKeyOk(key) {
			return nil, false
		}
		if len(value) < 1 || len(value) > maxEnvValueLength {
			return nil, false
		}
		if controlBytes.MatchString(value) || shellChars.MatchString(value) || sensitive.MatchString(value) {
			return nil, false
		}
		out[key] = value
	}
	return out, true
}

func bindValue(descriptor any, slot CommandPlaceSlot) (string, bool) {
	switch slot.Kind {
	case slotBoolean:
		b, ok := descriptor.(bool)
		if !ok {
			return "", false
		}
		if b {
			return "true", true
		}
		return "false", true
	case slotInteger:
		n, ok := descriptor.(int)
		if !ok {
			return "", false
		}
		if (slot.HasMin && n < slot.Min) || (slot.HasMax && n > slot.Max) {
			return "", false
		}
		return itoa(n), true
	default:
		value, ok := descriptor.(string)
		if !ok {
			return "", false
		}
		value = safeString(value, slot.Length, true)
		if value == "" {
			return "", false
		}
		return value, true
	}
}

func contained(root, file string, flavor PathFlavor) bool {
	sep := string(sepFor(flavor))
	trimmed := strings.TrimRight(root, sep)
	if trimmed == "" {
		return false
	}
	if !strings.HasPrefix(file, trimmed) {
		return false
	}
	if len(trimmed) <= 1 {
		return true
	}
	return strings.HasPrefix(file, trimmed+sep)
}

func containsAny(roots []string, executable string, flavor PathFlavor) bool {
	for _, root := range roots {
		if contained(root, executable, flavor) {
			return true
		}
	}
	return false
}

func sepFor(flavor PathFlavor) string {
	if flavor == flavorWin32 {
		return "\\"
	}
	return "/"
}

func reservedWin32(part string) bool {
	if regexp.MustCompile(`[<>:"|?*]`).MatchString(part) {
		return true
	}
	if regexp.MustCompile(`^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?$`).MatchString(strings.ToUpper(part)) {
		return true
	}
	return false
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [32]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func toStr(v any) string {
	switch value := v.(type) {
	case string:
		return value
	case bool:
		if value {
			return "true"
		}
		return "false"
	case int:
		return itoa(value)
	default:
		return ""
	}
}

// win32Clean collapses . and .. segments for a drive-lettered path and returns
// the result only when already canonical, so hostile traversal cannot pass.
func win32Clean(raw string) string {
	if !regexp.MustCompile(`^[A-Za-z]:\\`).MatchString(raw) {
		return raw
	}
	drive := raw[:3]
	parts := strings.Split(raw[3:], "\\")
	cleaned := make([]string, 0, len(parts))
	for _, part := range parts {
		if part == "." {
			continue
		}
		if part == ".." {
			if len(cleaned) == 0 {
				return raw
			}
			if cleaned[len(cleaned)-1] == ".." {
				cleaned = append(cleaned, part)
			} else {
				cleaned = cleaned[:len(cleaned)-1]
			}
			continue
		}
		if part == "" {
			continue
		}
		cleaned = append(cleaned, part)
	}
	return drive + strings.Join(cleaned, "\\")
}

// rootArg selects the "this is a root" grammar when set.
func rootArg(root []bool) bool { return len(root) > 0 && root[0] }

// canonicalPath validates and returns an exact absolute executable path, or "" on
// any deviation. root selects the root grammar.
func canonicalPath(raw string, flavor PathFlavor, max int, root ...bool) string {
	if len(raw) < 1 || len(raw) > max || controlBytes.MatchString(raw) || sensitive.MatchString(raw) {
		return ""
	}
	if flavor == flavorWin32 {
		if !regexp.MustCompile(`^[A-Za-z]:\\`).MatchString(raw) {
			return ""
		}
		if contains(raw, '/') || strings.HasPrefix(raw, `\\`) || strings.Contains(raw, `\\`) {
			return ""
		}
		if strings.Contains(raw, "..") {
			return ""
		}
		parts := raw[3:]
		if parts == "" {
			return ""
		}
		for _, part := range strings.Split(parts, "\\") {
			if part == "" || part == "." {
				return ""
			}
			if part == ".." || reservedWin32(part) {
				return ""
			}
		}
		if !rootArg(root) && strings.HasSuffix(raw, "\\") {
			return ""
		}
		if win32Clean(raw) != raw {
			return ""
		}
		return raw
	}
	// posix
	if shellChars.MatchString(raw) || contains(raw, '\\') || !strings.HasPrefix(raw, "/") || strings.Contains(raw, "//") {
		return ""
	}
	if path.Clean(raw) != raw || strings.Contains(raw, "..") {
		return ""
	}
	if !rootArg(root) && (raw == "/" || strings.HasSuffix(raw, "/")) {
		return ""
	}
	return raw
}
