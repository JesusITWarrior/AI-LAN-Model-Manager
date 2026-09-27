package provider

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

type Action string
type Outcome string
type RuntimeState string

const (
	ActionLoad   Action = "load"
	ActionUnload Action = "unload"

	OutcomeSucceeded Outcome = "succeeded"

	RuntimeLoaded   RuntimeState = "loaded"
	RuntimeUnloaded RuntimeState = "unloaded"

	KeepAliveMinimum = time.Second
	KeepAliveMaximum = 24 * time.Hour

	MaximumCommandIDLength   = 128
	MaximumCommandNameLength = 256
	MaximumContextLength     = 10_000_000
)

var ErrInvalidCommand = errors.New("invalid lifecycle command")

var (
	commandIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
	commandDigest    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
)

// Metadata is optional, validated provider metadata. It is never serialized to
// an Ollama lifecycle request.
type Metadata struct {
	ContextLength uint64
	Known         bool
}

type LoadModelCommand struct {
	commandID          string
	providerID         string
	canonicalName      string
	keepAlive          time.Duration
	contextLength      uint64
	contextLengthKnown bool
}

type UnloadModelCommand struct {
	commandID          string
	providerID         string
	canonicalName      string
	contextLength      uint64
	contextLengthKnown bool
}

func NewLoadModelCommand(commandID, providerID, model string, keepAlive time.Duration, metadata Metadata) (LoadModelCommand, error) {
	canonical, ok := CanonicalOllamaModelName(model)
	if !ok {
		return LoadModelCommand{}, ErrInvalidCommand
	}
	command := LoadModelCommand{commandID: commandID, providerID: providerID, canonicalName: canonical, keepAlive: keepAlive, contextLength: metadata.ContextLength, contextLengthKnown: metadata.Known}
	if err := command.Validate(); err != nil {
		return LoadModelCommand{}, err
	}
	return command, nil
}

func NewUnloadModelCommand(commandID, providerID, model string, metadata Metadata) (UnloadModelCommand, error) {
	canonical, ok := CanonicalOllamaModelName(model)
	if !ok {
		return UnloadModelCommand{}, ErrInvalidCommand
	}
	command := UnloadModelCommand{commandID: commandID, providerID: providerID, canonicalName: canonical, contextLength: metadata.ContextLength, contextLengthKnown: metadata.Known}
	if err := command.Validate(); err != nil {
		return UnloadModelCommand{}, err
	}
	return command, nil
}

func (c LoadModelCommand) CommandID() string          { return c.commandID }
func (c LoadModelCommand) ProviderID() string         { return c.providerID }
func (c LoadModelCommand) CanonicalName() string      { return c.canonicalName }
func (c LoadModelCommand) KeepAlive() time.Duration   { return c.keepAlive }
func (c LoadModelCommand) ContextLength() uint64      { return c.contextLength }
func (c LoadModelCommand) ContextLengthKnown() bool   { return c.contextLengthKnown }
func (c LoadModelCommand) Action() Action             { return ActionLoad }
func (c UnloadModelCommand) CommandID() string        { return c.commandID }
func (c UnloadModelCommand) ProviderID() string       { return c.providerID }
func (c UnloadModelCommand) CanonicalName() string    { return c.canonicalName }
func (c UnloadModelCommand) KeepAlive() time.Duration { return 0 }
func (c UnloadModelCommand) ContextLength() uint64    { return c.contextLength }
func (c UnloadModelCommand) ContextLengthKnown() bool { return c.contextLengthKnown }
func (c UnloadModelCommand) Action() Action           { return ActionUnload }

func (c LoadModelCommand) Validate() error {
	if !validCommandIdentity(c.commandID, c.providerID, c.canonicalName) || c.keepAlive < KeepAliveMinimum || c.keepAlive > KeepAliveMaximum || c.keepAlive%time.Second != 0 || !validContext(c.contextLength, c.contextLengthKnown) {
		return ErrInvalidCommand
	}
	return nil
}

func (c UnloadModelCommand) Validate() error {
	if !validCommandIdentity(c.commandID, c.providerID, c.canonicalName) || !validContext(c.contextLength, c.contextLengthKnown) {
		return ErrInvalidCommand
	}
	return nil
}

func validCommandIdentity(commandID, providerID, model string) bool {
	canonical, ok := CanonicalOllamaModelName(model)
	return commandIDPattern.MatchString(commandID) && ValidateProviderID(providerID) && ok && canonical == model
}

func validContext(value uint64, known bool) bool {
	if !known {
		return value == 0
	}
	return value >= 1 && value <= MaximumContextLength
}

// CanonicalOllamaModelName is the shared canonical-name rule used by lifecycle
// commands. It deliberately matches the Ollama inventory/running grammar.
func CanonicalOllamaModelName(value string) (string, bool) {
	if len(value) < 1 || len(value) > MaximumCommandNameLength || strings.TrimSpace(value) != value {
		return "", false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || strings.ContainsRune("?#\\%", character) || !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-/:@", character)) {
			return "", false
		}
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." || strings.HasPrefix(segment, ".") || strings.HasSuffix(segment, ".") {
			return "", false
		}
	}
	if strings.Count(value, "@") > 1 {
		return "", false
	}
	if at := strings.IndexByte(value, '@'); at >= 0 {
		if at == 0 || !strings.HasPrefix(strings.ToLower(value[at+1:]), "sha256:") || !commandDigest.MatchString(value[at+8:]) {
			return "", false
		}
	}
	return strings.ToLower(value), true
}

type LifecycleResult struct {
	CommandID          string       `json:"commandId"`
	ProviderID         string       `json:"providerId"`
	CanonicalModelName string       `json:"canonicalModelName"`
	Action             Action       `json:"action"`
	Outcome            Outcome      `json:"outcome"`
	Changed            bool         `json:"changed"`
	RuntimeState       RuntimeState `json:"runtimeState"`
	ObservedAt         string       `json:"observedAt"`
}
