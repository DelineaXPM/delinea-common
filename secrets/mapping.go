package secrets

import (
	"fmt"
	"strconv"
	"strings"
)

// Mapping describes one secret field to resolve and the output name to bind it
// to. EnvName is historical: resolved names are sink-neutral and may include the
// dots and hyphens Azure Pipelines accepts. A sink that creates environment
// variables must enforce ValidEnvName before delivery.
// Construct with ParseMapping, or directly: every field is exported.
type Mapping struct {
	EnvName  string
	Prefix   string
	ByPath   bool
	SecretID int
	Path     string
	Field    string
	Expand   bool
}

// Ref names the secret a mapping resolves against, for diagnostics and error text.
func (m Mapping) Ref() string {
	if m.ByPath {
		return "path " + m.Path
	}
	return "id " + strconv.Itoa(m.SecretID)
}

// cacheKey identifies the secret a mapping resolves against, so mappings sharing
// a secret fetch it once. The prefix keeps a numeric id from colliding with a path.
func (m Mapping) cacheKey() string {
	if m.ByPath {
		return "@" + m.Path
	}
	return "#" + strconv.Itoa(m.SecretID)
}

// ParseMapping parses one CLI-style mapping: NAME=field#id, NAME=field@path,
// PREFIX_*=#id, or PREFIX_*=@path.
//
// The separator names the kind of reference: "#" an id, "@" a folder path. Both
// characters are impossible in a field, because Secret Server rewrites them to
// "-" when it generates a slug, so the first occurrence of either is always the
// separator and a path may contain both. The field is required: defaulting it to
// "password" meant DB_USER=126 silently resolved to the password field, and the
// default was wrong outright for a template with no password field.
func ParseMapping(a string) (Mapping, error) {
	name, ref, ok := strings.Cut(a, "=")
	if !ok {
		return Mapping{}, fmt.Errorf("invalid mapping %q: want NAME=field#id or NAME=field@path", a)
	}
	if name == "" {
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty variable name", a)
	}
	expand := strings.HasSuffix(name, "*")
	if expand {
		name = strings.TrimSuffix(name, "*")
	}
	// Keep the parser sink-neutral: Azure Pipelines macro variables admit dots
	// and hyphens, while shell and GitHub delivery narrow names later with
	// ValidEnvName. The shared grammar still excludes whitespace, metacharacters,
	// Unicode, and leading punctuation. An expansion with an empty prefix is
	// refused outright: it would let a secret's field slugs name top-level
	// variables directly (PREFIX_ namespacing is what keeps an attacker-chosen
	// slug from becoming LD_PRELOAD), and validating the empty string here is
	// not enough because the generated names are only assembled later.
	if expand && name == "" {
		return Mapping{}, fmt.Errorf("invalid mapping %q: an expansion needs a non-empty prefix (PREFIX_*=...), so its generated names are namespaced", a)
	}
	if !validVariableName(name) {
		return Mapping{}, fmt.Errorf("invalid mapping %q: %q is not a valid variable name (%s)", a, name, variableNameRule)
	}

	at := strings.IndexAny(ref, "#@")
	if at < 0 {
		return Mapping{}, fmt.Errorf("invalid mapping %q: needs a field and a reference, as field#id or field@path", a)
	}
	field, target := ref[:at], ref[at+1:]
	byPath := ref[at] == '@'

	switch {
	case target == "" && byPath:
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty secret path", a)
	case target == "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: empty secret id", a)
	case expand && field != "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: PREFIX_* takes no field", a)
	case !expand && field == "":
		return Mapping{}, fmt.Errorf("invalid mapping %q: needs a field, as field#id or field@path", a)
	}

	if byPath {
		return Mapping{EnvName: name, Prefix: prefixIf(expand, name), ByPath: true, Path: target, Field: field, Expand: expand}.normalised(), nil
	}
	id, err := strconv.Atoi(target)
	if err != nil {
		return Mapping{}, fmt.Errorf("invalid secret id in %q: %w", a, err)
	}
	if id <= 0 {
		return Mapping{}, fmt.Errorf("invalid secret id in %q: id must be positive", a)
	}
	return Mapping{EnvName: name, Prefix: prefixIf(expand, name), SecretID: id, Field: field, Expand: expand}.normalised(), nil
}

func prefixIf(expand bool, name string) string {
	if expand {
		return name
	}
	return ""
}

// variableNameRule is the sink-neutral mapping grammar. It is the union needed
// by the supported sinks: environment identifiers plus Azure Pipelines dots and
// hyphens. Individual sinks may impose a narrower rule.
const variableNameRule = "letters, digits, underscore, dot, or hyphen; not starting with a digit, dot, or hyphen"

// ValidEnvName reports whether s is a well-formed environment-variable name:
// letters, digits, and underscores, not starting with a digit. Environment,
// shell, and GitHub sinks apply this narrower rule after sink-neutral mapping
// resolution.
func ValidEnvName(s string) bool { return validEnvName(s) }

// ValidVariableName reports whether s is a safe sink-neutral mapping name. It
// accepts the environment-name grammar plus dots and hyphens after the first
// character, matching Azure Pipelines macro variables without admitting shell
// metacharacters or ambiguous leading punctuation.
func ValidVariableName(s string) bool { return validVariableName(s) }

func validVariableName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case i > 0 && (r >= '0' && r <= '9' || r == '.' || r == '-'):
		default:
			return false
		}
	}
	return true
}

// validEnvName reports whether s is a POSIX-shell-safe environment variable
// name: an initial letter or underscore, then letters, digits, or underscores.
// This both keeps a shell metacharacter (backtick, $, ;, space) out of the
// name emitted by --via sh and forces an expansion prefix to be an identifier
// so PREFIX_<slug> stays well-formed.
func validEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		switch {
		case r == '_':
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9' && i > 0:
		default:
			return false
		}
	}
	return true
}

// normalised clears EnvName for an expansion, which names variables by prefix.
func (m Mapping) normalised() Mapping {
	if m.Expand {
		m.EnvName = ""
	}
	return m
}

func envify(slug string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(slug) {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	return b.String()
}
