package main

// Dons (Stripe) : badge « donor » sur le profil et role Discord, attribues automatiquement.
//
// Parcours :
//  1. La page donate.html envoie le joueur connecte vers le lien de paiement Stripe avec
//     ?client_reference_id=<son PID>. Un don fait sans etre connecte n'a pas de reference :
//     il est accepte, mais ne donne pas de badge (on ne sait pas a qui).
//  2. Stripe appelle POST /api/stripe/webhook quand le paiement est encaisse
//     (checkout.session.completed). L'appel est SIGNE : sans la signature valide, calculee
//     avec le secret du webhook, la requete est refusee. Sans secret configure, tout est
//     refuse (jamais de badge sur un appel non verifie).
//  3. Le compte est marque donateur, pour toujours (decision du 07/10/2026 : don ponctuel,
//     badge definitif, des le premier don).
//  4. Le bot Discord lit GET /api/admin/donors (cle de service) et donne le role aux membres
//     relies a un compte donateur.
//
// Le secret est lu dans le fichier stripe_webhook_secret.txt a cote des donnees OAuth (ou dans
// STRIPE_WEBHOOK_SECRET). Il n'est jamais journalise.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// lienDon : seul ce lien de paiement donne un badge. Un autre produit vendu un jour sur le
// meme compte Stripe ne doit pas en donner. A fournir dans NEXTENDO_DON_PAYMENT_LINK (plink_...).
func lienDon() string {
	if v := strings.TrimSpace(os.Getenv("NEXTENDO_DON_PAYMENT_LINK")); v != "" {
		return v
	}
	return "" // non configure : aucun paiement ne correspond, donc aucun badge (refus par defaut)
}

func secretStripe() string {
	if v := strings.TrimSpace(os.Getenv("STRIPE_WEBHOOK_SECRET")); v != "" {
		return v
	}
	b, err := os.ReadFile(filepath.Join(oauthDataDir(), "stripe_webhook_secret.txt"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// signatureStripeValide : en-tete « Stripe-Signature: t=<unix>,v1=<hex>[,v1=...] ». La
// signature est HMAC-SHA256(secret, "<t>.<corps>"). On refuse aussi un horodatage vieux de
// plus de 5 minutes, pour qu'un appel capture ne puisse pas etre rejoue plus tard.
func signatureStripeValide(entete string, corps []byte, secret string, maintenant time.Time) bool {
	if secret == "" || entete == "" {
		return false
	}
	var t string
	var sigs []string
	for _, part := range strings.Split(entete, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			t = kv[1]
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	ts, err := strconv.ParseInt(t, 10, 64)
	if err != nil {
		return false
	}
	if d := maintenant.Unix() - ts; d > 300 || d < -300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(t + "."))
	mac.Write(corps)
	attendu := mac.Sum(nil)
	for _, s := range sigs {
		recu, err := hex.DecodeString(s)
		if err == nil && hmac.Equal(recu, attendu) {
			return true
		}
	}
	return false
}

// SetDonor marque un compte comme donateur. Idempotent : un second don ne change rien et
// ne reecrit pas le disque.
func (s *jsonStore) SetDonor(id int64, depuis time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return false, ErrNotFound
	}
	if a.DonorSinceMs > 0 {
		return false, nil
	}
	a.DonorSinceMs = depuis.UnixMilli()
	return true, s.persist()
}

// stripeWebhook : POST /api/stripe/webhook, appele par Stripe.
func (s *server) stripeWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	corps, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "corps illisible")
		return
	}
	if !signatureStripeValide(r.Header.Get("Stripe-Signature"), corps, secretStripe(), time.Now()) {
		log.Printf("[dons] webhook REFUSE : signature absente ou invalide")
		writeErr(w, http.StatusBadRequest, "signature invalide")
		return
	}
	var ev struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Data struct {
			Object struct {
				ID                string `json:"id"`
				PaymentStatus     string `json:"payment_status"`
				PaymentLink       string `json:"payment_link"`
				ClientReferenceID string `json:"client_reference_id"`
				AmountTotal       int64  `json:"amount_total"`
				Currency          string `json:"currency"`
				Livemode          bool   `json:"livemode"`
			} `json:"object"`
		} `json:"data"`
	}
	if json.Unmarshal(corps, &ev) != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	// Toujours 200 a partir d'ici : l'appel est authentique, le rejouer ne changerait rien.
	o := ev.Data.Object
	if ev.Type != "checkout.session.completed" {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ignore": ev.Type})
		return
	}
	if o.PaymentStatus != "paid" || o.AmountTotal <= 0 || !o.Livemode || lienDon() == "" || o.PaymentLink != lienDon() {
		log.Printf("[dons] %s ignore : statut=%s montant=%d reel=%v lien=%s", ev.ID, o.PaymentStatus, o.AmountTotal, o.Livemode, o.PaymentLink)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "ignore": "non eligible"})
		return
	}
	// Tout don encaisse compte pour l'objectif du mois, avec ou sans compte.
	noteDon(o.ID, o.AmountTotal, time.Now())
	pid, perr := strconv.ParseUint(strings.TrimSpace(o.ClientReferenceID), 10, 64)
	if perr != nil || pid == 0 {
		log.Printf("[dons] %s : don de %d %s sans compte (reference %q), pas de badge", ev.ID, o.AmountTotal, o.Currency, o.ClientReferenceID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "badge": false})
		return
	}
	acct, aerr := s.store.ByPID(pid)
	js, estJSON := s.store.(*jsonStore)
	if aerr != nil || acct == nil || !estJSON {
		log.Printf("[dons] %s : don de %d %s pour le PID %d inconnu, pas de badge", ev.ID, o.AmountTotal, o.Currency, pid)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "badge": false})
		return
	}
	nouveau, serr := js.SetDonor(acct.ID, time.Now())
	if serr != nil {
		log.Printf("[dons] %s : echec d'enregistrement pour le PID %d : %v", ev.ID, pid, serr)
		writeErr(w, http.StatusInternalServerError, "enregistrement") // Stripe reessaiera
		return
	}
	log.Printf("[dons] %s : don de %d %s, PID %d donateur (nouveau=%v)", ev.ID, o.AmountTotal, o.Currency, pid, nouveau)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "badge": true})
}

// adminDonors : GET /api/admin/donors (cle de service du bot, ou session admin). Liste les
// identifiants Discord des comptes donateurs relies a Discord, pour le role.
func (s *server) adminDonors(w http.ResponseWriter, r *http.Request) {
	if !s.adminOrServiceKey(w, r) {
		return
	}
	js, ok := s.store.(*jsonStore)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"discord_ids": []string{}})
		return
	}
	ids := []string{}
	total := 0
	js.mu.RLock()
	for _, a := range js.Accts {
		if a.DonorSinceMs > 0 {
			total++
			if a.DiscordID != "" {
				ids = append(ids, a.DiscordID)
			}
		}
	}
	js.mu.RUnlock()
	writeJSON(w, http.StatusOK, map[string]any{"discord_ids": ids, "donors": total})
}

// ---- Objectif mensuel (barre de la page donate.html) ----
//
// Journal des dons encaisses : dons_journal.json a cote des donnees OAuth. Une entree par
// session de paiement Stripe (cle = identifiant de session, donc un appel rejoue par Stripe ne
// compte pas deux fois). On n'y garde que la date et le montant, rien sur le donateur.

type donNote struct {
	Ms    int64 `json:"ms"`
	Cents int64 `json:"cents"`
}

var donsMu sync.Mutex

func cheminJournalDons() string { return filepath.Join(oauthDataDir(), "dons_journal.json") }

func lireJournalDons() map[string]donNote {
	j := map[string]donNote{}
	if b, err := os.ReadFile(cheminJournalDons()); err == nil {
		_ = json.Unmarshal(b, &j)
	}
	return j
}

func noteDon(session string, cents int64, quand time.Time) {
	if session == "" || cents <= 0 {
		return
	}
	donsMu.Lock()
	defer donsMu.Unlock()
	j := lireJournalDons()
	if _, deja := j[session]; deja {
		return
	}
	j[session] = donNote{Ms: quand.UnixMilli(), Cents: cents}
	b, err := json.Marshal(j)
	if err != nil {
		return
	}
	tmp := cheminJournalDons() + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, cheminJournalDons())
	}
}

// objectifDonCents : objectif mensuel en centimes d'euro (150 EUR par defaut).
func objectifDonCents() int64 {
	if v, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("NEXTENDO_DON_GOAL_CENTS")), 10, 64); err == nil && v > 0 {
		return v
	}
	return 15000
}

// donGoal : GET /api/donations/goal, public. Total des dons du mois en cours (UTC) et objectif.
func (s *server) donGoal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, http.StatusMethodNotAllowed, "GET attendu")
		return
	}
	now := time.Now().UTC()
	debut := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	donsMu.Lock()
	j := lireJournalDons()
	donsMu.Unlock()
	var total int64
	for _, d := range j {
		if d.Ms >= debut {
			total += d.Cents
		}
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"month": now.Format("2006-01"), "month_cents": total, "goal_cents": objectifDonCents(), "currency": "eur",
	})
}

// adminSetDonor : POST /api/admin/donor?pid=<PID> (cle de service ou session admin). Donne le
// badge a la main, pour un don fait sans etre connecte au site ou hors Stripe. Le role Discord
// suit par le bot, comme pour un don normal.
func (s *server) adminSetDonor(w http.ResponseWriter, r *http.Request) {
	if !s.adminOrServiceKey(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	pid, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("pid")), 10, 64)
	js, ok := s.store.(*jsonStore)
	if err != nil || pid == 0 || !ok {
		writeErr(w, http.StatusBadRequest, "pid invalide")
		return
	}
	acct, aerr := s.store.ByPID(pid)
	if aerr != nil || acct == nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	nouveau, serr := js.SetDonor(acct.ID, time.Now())
	if serr != nil {
		writeErr(w, http.StatusInternalServerError, "enregistrement")
		return
	}
	log.Printf("[dons] badge donne a la main au PID %d (nouveau=%v)", pid, nouveau)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "pid": pid, "new": nouveau, "discord_linked": acct.DiscordID != ""})
}
