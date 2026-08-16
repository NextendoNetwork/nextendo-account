package main

// Gate « un seul endroit à la fois » (#5) basé sur la PRÉSENCE RÉELLE.
//
// Ancienne approche : un store de sessions interne (upsertPlaySession/activePlayElsewhere)
// mis à jour à l'auth + TTL. Problème : il se désynchronisait de la réalité -> « sessions
// fantômes » qui bloquaient un compte alors qu'il n'était plus connecté nulle part.
//
// Nouvelle approche (demandée) : la SOURCE DE VÉRITÉ = les serveurs de jeu eux-mêmes. Chaque
// serveur NEX expose /api/stats avec la liste des connexions PRUDP LIVE (c'est exactement ce
// qu'affiche le monitoring :8085). Règle simple :
//   - le PID apparaît dans /api/stats d'un serveur  => il est connecté => on REFUSE toute
//     nouvelle session (autre plateforme) ;
//   - il n'apparaît nulle part => il s'est déconnecté => la place est LIBRE.
//
// ⚠ On a longtemps cru qu'une connexion perdue disparaissait d'elle-même de /api/stats.
// C'est FAUX : le serveur de jeu garde le joueur listé indéfiniment (relevé en prod : des
// entrées à 24 h, 45 h, 47 h sans la moindre action). Le compte restait donc « en train de
// jouer ailleurs » pour toujours et son propriétaire ne pouvait plus revenir en ligne —
// il devait se recréer un compte (erreur 2306-0802). D'où le filtre sur idleSeconds
// ci-dessous : seule une session RÉCEMMENT active occupe la place.

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)

var gameStatsClient = &http.Client{Timeout: 2 * time.Second}

// URLs internes des serveurs de jeu (mêmes que celles que poll le monitoring nexdash).
func gameStatsURLs() []string {
	env := func(k, d string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return d
	}
	return []string{
		env("DASH_MK8_URL", "http://mk8nex:8082"),
		env("DASH_S2_URL", "http://s2nex:8083"),
		env("DASH_SSBU_URL", "http://ssbusecure:8084"),
		env("DASH_ACNH_URL", "http://acnhnex-nexgo:8086"),
		// ARMS's titlesByAccessKey entry (b6b34c51) was added without this: the mapping
		// existed but nothing ever polled ARMS's /api/stats, so it could never actually be
		// matched -- caught in review 2026-08-16. Container is just "arms", confirmed by
		// Kazu (matches what they already run in production, not a guess anymore).
		env("DASH_ARMS_URL", "http://arms:8091"),
	}
}

// ghostIdleSeconds : au-delà de ce temps sans la moindre action, une entrée de /api/stats
// est considérée comme une session morte et n'occupe plus la place du compte. Défaut 15 min,
// large au regard des joueurs réellement actifs (mesuré : 19 à 141 s, ~10 min au pire dans
// un menu) et bien en deçà des fantômes observés (77 min à 47 h). Réglable si besoin.
func ghostIdleSeconds() int64 {
	if v := os.Getenv("NEXTENDO_GHOST_IDLE_SECONDS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return 900
}

func gameStatsKey() string {
	// PAS de valeur de repli. L'ancienne était écrite en clair dans le source : quiconque
	// avait le dépôt — ou l'un des binaires compilés — pouvait interroger /api/stats de
	// n'importe quel serveur de jeu et lire la liste des joueurs (pseudos, PID, IP).
	// Si la variable manque, on préfère ne pas interroger plutôt que d'utiliser un secret publié.
	return os.Getenv("DASH_TOKEN")
}

// pidPlayingNow : le PID est-il ACTUELLEMENT connecté à un serveur de jeu (= visible dans le
// monitoring) ? Interroge les /api/stats. Fail-safe : en cas d'erreur réseau on considère
// "pas vu ici" (on ne bloque pas sur un hoquet -> on ne verrouille jamais tout le monde).
func pidPlayingNow(pid uint64) (bool, string) {
	key := gameStatsKey()
	for _, base := range gameStatsURLs() {
		u := base + "/api/stats?key=" + key
		resp, err := gameStatsClient.Get(u)
		if err != nil {
			continue
		}
		var s struct {
			Game    string `json:"game"`
			Players []struct {
				PID         uint64 `json:"pid"`
				IdleSeconds int64  `json:"idleSeconds"`
			} `json:"players"`
		}
		derr := json.NewDecoder(resp.Body).Decode(&s)
		resp.Body.Close()
		if derr != nil {
			continue
		}
		for _, p := range s.Players {
			if p.PID != pid {
				continue
			}
			// SESSION FANTÔME. Un joueur qui perd sa connexion (crash, coupure, émulateur
			// fermé) reste listé indéfiniment par le serveur de jeu : relevé en prod, des
			// entrées à 24 h, 45 h, 47 h d'inactivité. La garde « un seul endroit » y voyait
			// quelqu'un en train de jouer et refusait l'entrée POUR TOUJOURS — d'où des
			// joueurs contraints de se recréer un compte pour revenir (erreur 2306-0802).
			// On ne considère donc « en train de jouer » qu'une session RÉCEMMENT active.
			if p.IdleSeconds > ghostIdleSeconds() {
				log.Printf("[online-check] pid=%d ignoré sur %s : session fantôme (inactif %ds)", pid, base, p.IdleSeconds)
				continue
			}
			return true, base
		}
	}
	return false, ""
}
