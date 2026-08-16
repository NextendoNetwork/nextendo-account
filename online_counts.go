package main

// Live per-game player counts for the emulator's game list ("N players online" next to each
// supported title).
//
// Source of truth is the same /api/stats the monitoring polls — the game servers already know
// exactly who is connected, so nothing new has to be tracked. We map a server to its titles by
// its NEX access key rather than by which URL answered: the URL is deployment config (it moves
// between hosts), the access key is a property of the game itself and cannot drift.
//
// Cached for a few seconds: every emulator on every machine polls this, and the answer only
// changes when someone joins or leaves.

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"
)

// titlesByAccessKey maps a game server's NEX access key to every title id it serves.
// A game has one access key but can have several regional title ids (Splatoon 2).
var titlesByAccessKey = map[string][]string{
	"09c1c475": {"0100152000022000"},                                         // Mario Kart 8 Deluxe
	"4eb18d39": {"0100f8f0000a2000", "01003bc0000a0000", "01003c700009c800"}, // Splatoon 2 (EU/US/JP)
	"9587602b": {"01006a800016e000"},                                         // Super Smash Bros. Ultimate
	"b6b34c51": {"01009b500007c000"},                                         // ARMS
	"v43a10em": {"01006f8002326000"},                                         // Animal Crossing: New Horizons
}

const onlineCountsTTL = 5 * time.Second

var (
	countsMu     sync.Mutex
	countsCache  map[string]int
	countsExpiry time.Time
)

// gameStatsSnapshot is the subset of a game server's /api/stats we need.
type gameStatsSnapshot struct {
	Connected int `json:"connected"`
	Server    struct {
		AccessKey string `json:"accessKey"`
	} `json:"server"`
}

// collectOnlineCounts asks every game server how many players it has and folds the answers
// into a title id -> count map. A server that doesn't answer contributes nothing (the count
// shows 0 rather than the whole endpoint failing).
func collectOnlineCounts() map[string]int {
	key := gameStatsKey()
	out := map[string]int{}
	for _, base := range gameStatsURLs() {
		resp, err := gameStatsClient.Get(base + "/api/stats?key=" + key)
		if err != nil {
			continue
		}
		var s gameStatsSnapshot
		derr := json.NewDecoder(resp.Body).Decode(&s)
		resp.Body.Close()
		if derr != nil {
			continue
		}
		titles, ok := titlesByAccessKey[strings.ToLower(s.Server.AccessKey)]
		if !ok {
			continue
		}
		for _, t := range titles {
			out[strings.ToLower(t)] = s.Connected
		}
	}
	return out
}

// onlineCounts serves { "<titleId>": <players online>, ... } for the emulator's game list.
// Public on purpose: it is the same number the monitoring page already shows to everyone, and
// requiring a token would mean shipping one in the client for no benefit.
func (s *server) onlineCounts(w http.ResponseWriter, r *http.Request) {
	countsMu.Lock()
	fresh := countsCache != nil && time.Now().Before(countsExpiry)
	cached := countsCache
	countsMu.Unlock()

	if !fresh {
		cached = collectOnlineCounts()
		countsMu.Lock()
		countsCache, countsExpiry = cached, time.Now().Add(onlineCountsTTL)
		countsMu.Unlock()
	}

	writeJSON(w, http.StatusOK, map[string]any{"counts": cached})
}
