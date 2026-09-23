package main

// Pays du compte Nextendo.
//
// À QUOI ÇA SERT : Mario Kart 8 affiche un drapeau à côté de chaque joueur en
// ligne. La console le tire de la fiche de compte Nintendo ; l'émulateur, lui,
// n'a aucune notion de pays (il ne connaît qu'une RÉGION : Europe, USA, Japon).
// Résultat, personne n'a de drapeau sur Nextendo. Le compte devient donc la
// source de vérité : le joueur choisit son pays ici, l'émulateur le lit à la
// connexion et le présente au jeu. Aucun mod du jeu, et ça vaut aussi pour une
// vraie console.
//
// CE QU'ON STOCKE : uniquement le code ISO 3166-1 alpha-2 (« FR », « BR », …).
// Pas les noms : le site les affiche via Intl.DisplayNames, qui les traduit dans
// la langue du visiteur. Une liste de noms écrite à la main aurait dû l'être en
// dix langues, et aurait vieilli.
//
// Un compte sans pays vaut « inconnu » — c'est le cas de tous les comptes
// existants, qui devront le renseigner.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// countryCodes : la liste ISO 3166-1 alpha-2, sans restriction. Y compris les
// territoires quasi inhabités (Antarctique, Svalbard, …) : le choix appartient
// au joueur, on ne présume pas d'où il est.
const countryCodes = `
AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL
BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV
CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD
GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IM IN
IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR
LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX
MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS
PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST
SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ
VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW
`

var countrySet = buildCountrySet()

func buildCountrySet() map[string]bool {
	m := map[string]bool{}
	for _, c := range strings.Fields(countryCodes) {
		m[c] = true
	}
	return m
}

// countryList rend les codes acceptés, triés, pour que le site construise son
// menu déroulant sans dupliquer la liste.
func countryList() []string {
	out := strings.Fields(countryCodes)
	for i := range out {
		out[i] = strings.ToUpper(out[i])
	}
	return out
}

// normalizeCountry met en forme et valide un code. Rend "" si le code n'est pas
// dans la liste — un compte sans pays est un état valide (« inconnu »).
func normalizeCountry(code string) string {
	c := strings.ToUpper(strings.TrimSpace(code))
	if countrySet[c] {
		return c
	}
	return ""
}

// SetCountry enregistre le pays du compte. Un code vide efface le pays.
func (s *jsonStore) SetCountry(id int64, code string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	a.Country = code
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

// country sert la liste des codes (GET, public) et enregistre le choix du
// joueur (POST, authentifié).
func (s *server) country(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024) // limit of 1kb
	// error out if too large
	if err := r.Body.Close(); err != nil {
		writeErr(w, http.StatusBadRequest, "Corps de requête trop volumineux")
		return
	}
	switch r.Method {
	case http.MethodGet:
		// Public : la page d'inscription en a besoin avant tout compte.
		writeJSON(w, http.StatusOK, map[string]any{"countries": countryList()})

	case http.MethodPost:
		acct, ok := s.accountFromBearer(r)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
			return
		}
		var in struct {
			Country string `json:"country"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "JSON invalide")
			return
		}
		code := normalizeCountry(in.Country)
		if code == "" {
			writeErr(w, http.StatusBadRequest, "Pays inconnu.")
			return
		}
		updated, err := s.store.SetCountry(acct.ID, code)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		// nx-account relit cette table pour remplir le champ "country" de l objet
		// BAAS : c est de la que Mario Kart tire le drapeau.
		writeCountryMap(s.store)
		writeJSON(w, http.StatusOK, map[string]any{"account": updated.Public()})

	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou POST attendu")
	}
}
