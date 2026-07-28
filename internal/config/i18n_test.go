package config_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/plattnericus/revpd/internal/config"
)

/*
	The settings page is drawn from this registry, but the words come from the
	frontend dictionaries — the labels have to be translated, and Go has no
	business holding ten languages.

	The two halves are joined by nothing but a string key, so they can drift
	apart in silence: a setting added here without a name there shows its own
	key as a label, which is how "auth.require_second_factor" once ended up
	printed on the security toggle. This test is the join.

	It reads the English blocks, which are the reference the frontend's own
	completeness check holds the other nine to.
*/

var entry = regexp.MustCompile(`(?m)^\s*'([a-z0-9_]+\.[a-z0-9_]+)':`)

func firstBlock(t *testing.T, path, opening, closing string) map[string]bool {
	t.Helper()

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	text := string(body)
	start := strings.Index(text, opening)
	if start < 0 {
		t.Fatalf("%s: no block starting %q — was it renamed?", path, opening)
	}
	text = text[start:]

	if end := strings.Index(text, closing); end > 0 {
		text = text[:end]
	}

	keys := map[string]bool{}
	for _, m := range entry.FindAllStringSubmatch(text, -1) {
		keys[m[1]] = true
	}
	if len(keys) == 0 {
		t.Fatalf("%s: found no entries in the English block", path)
	}
	return keys
}

func TestEverySettingHasAName(t *testing.T) {
	labels := firstBlock(t, "../../web/src/lib/i18n.settings.ts", "const en: Labels", "const de: Labels")

	for _, s := range config.Registry() {
		if !labels[s.Key] {
			t.Errorf("%s has no name in i18n.settings.ts — the page would show the key itself", s.Key)
		}
		delete(labels, s.Key)
	}
	for key := range labels {
		t.Errorf("i18n.settings.ts names %q, which is not a setting any more", key)
	}
}

// A setting explains itself in the reader's language or not at all. The server
// sends an English line as a fallback, and a fallback that is always used is
// just an untranslated interface.
func TestEveryExplainedSettingHasATranslatedHint(t *testing.T) {
	hints := firstBlock(t, "../../web/src/lib/i18n.hints.ts", "const de: Hints", "const en: Hints")

	for _, s := range config.Registry() {
		if s.Warn == "" {
			continue // several settings say enough with their name alone
		}
		if !hints[s.Key] {
			t.Errorf("%s has an English hint from the registry but no translation in i18n.hints.ts", s.Key)
		}
		delete(hints, s.Key)
	}
	for key := range hints {
		t.Errorf("i18n.hints.ts explains %q, which no longer has a hint here", key)
	}
}
