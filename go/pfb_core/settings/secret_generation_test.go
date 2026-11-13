package settings

import "testing"

// A generation is visible to every API client, so it must not confirm a guess of a secret (issue #3937: feed
// credentials are the first production secrets). Two values of a set secret give one generation; setting or clearing
// it, which a read shows, moves it.
func TestAGenerationCountsASecretOnlyByItsPresence(t *testing.T) {
	gen := func(password string) uint64 {
		t.Helper()
		st := open(t, t.TempDir())
		if _, err := st.Initialize(changes(t, `{"feedauth": {"user": "u", "password": "`+password+`"}}`)); err != nil {
			t.Fatal(err)
		}
		return projection(t, get(t, st, "feedauth"), "feedauth").Generation
	}
	if a, b := gen("guess-one"), gen("guess-two"); a != b {
		t.Errorf("passwords guess-one and guess-two give generations %d and %d: the generation tells them apart", a, b)
	}
	if set, unset := gen("guess-one"), gen(""); set == unset {
		t.Errorf("a set and an unset password give the same generation %d: a read shows the difference", set)
	}
}
