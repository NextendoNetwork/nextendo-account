// Nextendo Network — account service.
//
// This is the account layer that sits in FRONT of the
// existing dauth/aauth/baas + NEX stack. It serves:
//   - the public website (static/)
//   - a small JSON API for account creation + login
//
// An account = a persistent identity (username/email/password) mapped to a NEX
// principal id (PID, the same 1800000xxx space the auth server already uses) and
// a Switch-style friend code. M2 wires this account login into the baas/NEX auth
// chain so logging in with your Nextendo account puts YOU online in-game.
//
// Storage is behind a tiny interface: a zero-setup JSON file for local testing
// (just `go run .`), and Postgres (DATABASE_URL) for the VPS deployment (M2).
package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ---------------------------------------------------------------------------
// Model
// ---------------------------------------------------------------------------

// Account is one Nextendo Network identity.
type Account struct {
	ID            int64     `json:"id"`
	Username      string    `json:"username"`
	Email         string    `json:"email"`
	PasswordHash  string    `json:"password_hash"` // stored in accounts.json; never sent to clients (responses use Public())
	PID           uint64    `json:"pid"`           // NEX principal id (1800000xxx)
	FriendCode    string    `json:"friend_code"`   // SW-XXXX-XXXX-XXXX
	CreatedAt     time.Time `json:"created_at"`
	EmailVerified bool      `json:"email_verified"`     // true once the user clicked the e-mailed verification link
	Disabled      bool      `json:"disabled,omitempty"` // gel de relance : true = compte fermé (connexion site bloquée + refusé en ligne). Réversible.
	RegIP         string    `json:"reg_ip,omitempty"`   // IP d'inscription — réservée si le compte est banni

	// Lien Discord poussé par le bot de vérif (voir discord.go). Le compte est la source de
	// vérité : le gate online peut l'exiger, et un ban depuis le site sait qui bannir sur Discord.
	DiscordID       string    `json:"discord_id,omitempty"`
	DiscordUsername string    `json:"discord_username,omitempty"`
	DiscordLinkedAt time.Time `json:"discord_linked_at,omitempty"`
	Profile         *Profile  `json:"profile,omitempty"`         // synced in-game identity (nickname/avatar/Mii)
	Friends         []uint64  `json:"friends,omitempty"`         // friend PIDs (mutual, accepted)
	FriendRequests  []uint64  `json:"friend_requests,omitempty"` // incoming request PIDs (pending)
	Blocked         []uint64  `json:"blocked,omitempty"`         // PIDs this account blocked (no requests/friendship)

	// Synthetic Nintendo-Account / BAAS ids served to a REAL CFW Switch so the
	// console caches a NEXTENDO identity, NEVER the user's real Nintendo account.
	// Derived once from PID via HMAC(session secret); by construction they can
	// never equal a real Nintendo id. This is what makes Nextendo mode
	// corruption-free (consumed by nx-account via /internal/identity).
	NaID   string `json:"na_id,omitempty"`
	BaasID string `json:"baas_id,omitempty"`
	BsDid  string `json:"bs_did,omitempty"`
}

// Profile is the in-game identity bound to the account and synced by the
// emulator (the account is authoritative, the console pulls it
// on login). Name = Switch profile nickname, Image = base64 JPEG avatar,
// Mii = base64 of the Switch Mii blob (CharInfo/StoreData).
type Profile struct {
	Name      string    `json:"name,omitempty"`
	Image     string    `json:"image,omitempty"`
	Mii       string    `json:"mii,omitempty"`
	Avatar    string    `json:"avatar,omitempty"` // id d'icône de la galerie Nextendo (sélecteur web ; vide si photo importée/Mii)
	Color     string    `json:"color,omitempty"`  // couleur de fond (hex #rrggbb) de la photo de profil
	UpdatedAt time.Time `json:"updated_at,omitempty"`
}

// Public is the safe view of an account returned to clients.
func (a *Account) Public() map[string]any {
	return map[string]any{
		"id":          a.ID,
		"username":    a.Username,
		"email":       a.Email,
		"pid":         a.PID,
		"friend_code": a.FriendCode,
		"created_at":  a.CreatedAt.Format(time.RFC3339),
		// Guests have a synthetic @nextendo.local e-mail with nothing to verify → treat as verified.
		"email_verified": a.EmailVerified || a.IsGuest(),
		// Lien Discord poussé par le bot de vérif (voir discord.go). Public() ne décrit QUE le
		// compte du porteur du token (register/login/me/…), jamais un tiers : le pseudo Discord
		// n'est donc montré qu'à son propriétaire, sur /compte.
		"discord":           a.DiscordUsername,
		"discord_linked_at": discordLinkedAtStr(a),
	}
}

func discordLinkedAtStr(a *Account) string {
	if a.DiscordLinkedAt.IsZero() {
		return ""
	}
	return a.DiscordLinkedAt.UTC().Format(time.RFC3339)
}

// IsGuest reports whether this is a no-account GUEST profile (created via /api/guest, which
// uses a synthetic guest-…@nextendo.local e-mail). Guests are excluded from full-account-only
// features — currently cloud saves (beta).
func (a *Account) IsGuest() bool {
	return strings.HasSuffix(strings.ToLower(a.Email), "@nextendo.local")
}

// deriveID makes a STABLE synthetic 16-hex id from a PID, keyed by the session
// secret and domain-separated by kind ("na"/"baas"/"bsdid"). Used for the
// Nintendo-Account/BAAS ids we serve to a real CFW Switch: the console then
// caches a Nextendo identity that can never collide with a real Nintendo id.
func deriveID(secret []byte, kind string, pid uint64) string {
	h := hmac.New(sha256.New, secret)
	fmt.Fprintf(h, "%s:%d", kind, pid)
	return hex.EncodeToString(h.Sum(nil)[:8]) // 16 hex chars, like a real naID
}

// ensureNintendoIDs fills NaID/BaasID/BsDid if empty (derived from PID). Returns
// true if it changed anything so the caller can persist. Requires loadSecret().
func (a *Account) ensureNintendoIDs() bool {
	changed := false
	if a.NaID == "" {
		a.NaID = deriveID(sessionSecret, "na", a.PID)
		changed = true
	}
	if a.BaasID == "" {
		a.BaasID = deriveID(sessionSecret, "baas", a.PID)
		changed = true
	}
	if a.BsDid == "" {
		a.BsDid = deriveID(sessionSecret, "bsdid", a.PID)
		changed = true
	}
	return changed
}

// firstNexPID matches the auth server's user PID space (1800000000+). The auth
// server hands out placeholder PIDs today; in M2 it will look the real PID up
// from this account store instead.
const firstNexPID uint64 = 1800000000

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

var (
	ErrTaken    = errors.New("username or email already taken")
	ErrNotFound = errors.New("account not found")
)

type Store interface {
	Create(username, email, passwordHash string) (*Account, error)
	ByLogin(login string) (*Account, error) // username OR email
	ByID(id int64) (*Account, error)
	ByPID(pid uint64) (*Account, error)
	ByFriendCode(code string) (*Account, error)
	SetProfile(id int64, p *Profile) (*Account, error)
	SetUsername(id int64, username string) (*Account, error)
	SetPassword(id int64, passwordHash string) error
	SetEmailVerified(id int64, verified bool) error
	SetEmail(id int64, email string) (*Account, error)
	SetDisabled(id int64, disabled bool) error                            // gel de relance : ferme/rouvre un compte
	SetRegIP(id int64, ip string) error                                   // ban : capture l'IP d'inscription (réservée au ban)
	SetDiscordLink(id int64, discordID, username string) error            // lien Discord poussé par le bot (gate online + ban miroir)
	LockdownExcept(keepPID uint64) (int, error)                           // ferme TOUS les comptes sauf keepPID (et le vérifie/rouvre)
	EnableAll() (int, error)                                              // annule le gel : rouvre tous les comptes
	AllAccounts() []*Account                                              // espace admin : liste tous les comptes
	DeleteByPID(pid uint64) error                                         // espace admin : supprime un compte
	SendFriendRequest(id int64, targetPID uint64) (*Account, bool, error) // (target, alreadyFriends, err)
	AcceptFriendRequest(id int64, fromPID uint64) (*Account, error)
	DeclineFriendRequest(id int64, fromPID uint64) error
	RemoveFriend(id int64, friendPID uint64) error
	BlockUser(id int64, targetPID uint64) error
	UnblockUser(id int64, targetPID uint64) error
}

// jsonStore is a concurrency-safe, file-backed store for local testing.
// It is deliberately simple; the Postgres store (M2) implements the same
// interface so nothing else changes.
type jsonStore struct {
	mu     sync.RWMutex
	path   string
	NextID int64              `json:"next_id"`
	NextP  uint64             `json:"next_pid"`
	Accts  map[int64]*Account `json:"accounts"`
	byUser map[string]int64   `json:"-"`
	byMail map[string]int64   `json:"-"`
	byPID  map[uint64]int64   `json:"-"`
	byCode map[string]int64   `json:"-"`
}

func newJSONStore(path string) (*jsonStore, error) {
	s := &jsonStore{
		path:   path,
		NextID: 1,
		NextP:  firstNexPID + 1,
		Accts:  map[int64]*Account{},
		byUser: map[string]int64{},
		byMail: map[string]int64{},
		byPID:  map[uint64]int64{},
		byCode: map[string]int64{},
	}
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, s); err != nil {
			return nil, fmt.Errorf("corrupt account file %s: %w", path, err)
		}
		if s.Accts == nil {
			s.Accts = map[int64]*Account{}
		}
		for id, a := range s.Accts {
			s.byUser[strings.ToLower(a.Username)] = id
			s.byMail[strings.ToLower(a.Email)] = id
			s.byPID[a.PID] = id
			s.byCode[a.FriendCode] = id
		}
		if s.NextID == 0 {
			s.NextID = 1
		}
		if s.NextP == 0 {
			s.NextP = firstNexPID + 1
		}
	}
	return s, nil
}

func (s *jsonStore) persist() error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *jsonStore) Create(username, email, passwordHash string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Le pseudo N'EST PLUS unique : plusieurs joueurs peuvent partager le même nom affiché
	// (ils se distinguent par leur friend code). Seul l'e-mail — la clé de connexion — reste unique.
	if _, ok := s.byMail[strings.ToLower(email)]; ok {
		return nil, ErrTaken
	}
	a := &Account{
		ID:           s.NextID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		PID:          s.NextP,
		FriendCode:   genFriendCode(),
		CreatedAt:    time.Now().UTC(),
	}
	a.ensureNintendoIDs() // synthetic Nintendo identity for real-Switch isolation
	s.Accts[a.ID] = a
	s.byUser[strings.ToLower(username)] = a.ID
	s.byMail[strings.ToLower(email)] = a.ID
	s.byPID[a.PID] = a.ID
	s.byCode[a.FriendCode] = a.ID
	s.NextID++
	s.NextP++
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *jsonStore) ByLogin(login string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	l := strings.ToLower(login)
	id, ok := s.byUser[l]
	if !ok {
		id, ok = s.byMail[l]
	}
	if !ok {
		return nil, ErrNotFound
	}
	return s.Accts[id], nil
}

func (s *jsonStore) ByID(id int64) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	return a, nil
}

func (s *jsonStore) SetProfile(id int64, p *Profile) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	p.UpdatedAt = time.Now().UTC()
	a.Profile = p
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *jsonStore) ByPID(pid uint64) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byPID[pid]
	if !ok {
		return nil, ErrNotFound
	}
	return s.Accts[id], nil
}

func (s *jsonStore) ByFriendCode(code string) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byCode[code]
	if !ok {
		return nil, ErrNotFound
	}
	return s.Accts[id], nil
}

// ByBaasNSA reverse-looks-up a REAL CFW Switch's NSA id to the owning account.
// The NSA id served to the console at account-link is deriveID("baas", pid) (16
// hex chars); the console stores it as a u64 and presents it at NEX login as that
// value in DECIMAL. The NEX auth calls /api/nsa with it so the console's NEX PID
// becomes the account PID (stable identity + pseudo) instead of a throwaway
// per-login counter. O(accounts) — fine for our scale.
func (s *jsonStore) ByBaasNSA(nsa uint64) (*Account, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.Accts {
		baas := a.BaasID
		if baas == "" {
			baas = deriveID(sessionSecret, "baas", a.PID)
		}
		if v, err := strconv.ParseUint(baas, 16, 64); err == nil && v == nsa {
			return a, nil
		}
	}
	return nil, ErrNotFound
}

func (s *jsonStore) SetUsername(id int64, username string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	low := strings.ToLower(username)
	// Pseudos non uniques (différenciés par friend code) : pas de contrôle de collision.
	// byUser reste un index best-effort "dernier propriétaire" (la connexion se fait par e-mail).
	delete(s.byUser, strings.ToLower(a.Username))
	a.Username = username
	s.byUser[low] = id
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

// SetPassword replaces the account's bcrypt hash (password reset). Changing the
// hash also invalidates any outstanding reset link (the token is bound to the old hash).
func (s *jsonStore) SetPassword(id int64, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	a.PasswordHash = passwordHash
	return s.persist()
}

// SetEmailVerified flips the account's e-mail-verified flag.
func (s *jsonStore) SetEmailVerified(id int64, verified bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	a.EmailVerified = verified
	return s.persist()
}

// SetEmail changes the account's e-mail (must be free) and marks it UNVERIFIED. The
// e-mail is the login key, so uniqueness is enforced here.
func (s *jsonStore) SetEmail(id int64, email string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	low := strings.ToLower(email)
	if other, ok := s.byMail[low]; ok && other != id {
		return nil, ErrTaken
	}
	delete(s.byMail, strings.ToLower(a.Email))
	a.Email = email
	a.EmailVerified = false
	s.byMail[low] = id
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

func addFriendPID(a *Account, pid uint64) {
	for _, p := range a.Friends {
		if p == pid {
			return
		}
	}
	a.Friends = append(a.Friends, pid)
}

func removeFriendPID(a *Account, pid uint64) {
	out := a.Friends[:0]
	for _, p := range a.Friends {
		if p != pid {
			out = append(out, p)
		}
	}
	a.Friends = out
}

func hasFriendPID(a *Account, pid uint64) bool {
	for _, p := range a.Friends {
		if p == pid {
			return true
		}
	}
	return false
}

func addReqPID(a *Account, pid uint64) {
	for _, p := range a.FriendRequests {
		if p == pid {
			return
		}
	}
	a.FriendRequests = append(a.FriendRequests, pid)
}

func removeReqPID(a *Account, pid uint64) {
	out := a.FriendRequests[:0]
	for _, p := range a.FriendRequests {
		if p != pid {
			out = append(out, p)
		}
	}
	a.FriendRequests = out
}

func hasReqPID(a *Account, pid uint64) bool {
	for _, p := range a.FriendRequests {
		if p == pid {
			return true
		}
	}
	return false
}

func hasBlockedPID(a *Account, pid uint64) bool {
	for _, p := range a.Blocked {
		if p == pid {
			return true
		}
	}
	return false
}

func addBlockedPID(a *Account, pid uint64) {
	if hasBlockedPID(a, pid) {
		return
	}
	a.Blocked = append(a.Blocked, pid)
}

func removeBlockedPID(a *Account, pid uint64) {
	out := a.Blocked[:0]
	for _, p := range a.Blocked {
		if p != pid {
			out = append(out, p)
		}
	}
	a.Blocked = out
}

// SendFriendRequest queues a pending request on the target (or, if the target had
// already requested us, accepts it → mutual). Returns (target, alreadyFriends, err).
func (s *jsonStore) SendFriendRequest(id int64, targetPID uint64) (*Account, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, false, ErrNotFound
	}
	tid, ok := s.byPID[targetPID]
	if !ok {
		return nil, false, ErrNotFound
	}
	b := s.Accts[tid]
	if a.PID == b.PID {
		return nil, false, errors.New("cannot add yourself")
	}
	if hasBlockedPID(b, a.PID) || hasBlockedPID(a, b.PID) {
		return nil, false, errors.New("blocked")
	}
	if hasFriendPID(a, b.PID) {
		return b, true, nil
	}
	if hasReqPID(a, b.PID) { // they already requested us → accept directly
		removeReqPID(a, b.PID)
		addFriendPID(a, b.PID)
		addFriendPID(b, a.PID)
		if err := s.persist(); err != nil {
			return nil, false, err
		}
		return b, true, nil
	}
	addReqPID(b, a.PID) // pending on the target's side
	if err := s.persist(); err != nil {
		return nil, false, err
	}
	return b, false, nil
}

// SentRequestPIDs returns the PIDs this account has an OUTGOING (pending) friend
// request to. Outgoing requests aren't stored directly (SendFriendRequest only
// records on the receiver's incoming list), so we derive them: every account whose
// incoming FriendRequests contains pid has a pending request FROM pid. Powers the
// Home-Menu "sent requests" (outbox) tab.
func (s *jsonStore) SentRequestPIDs(pid uint64) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []uint64{}
	for _, a := range s.Accts {
		for _, rp := range a.FriendRequests {
			if rp == pid {
				out = append(out, a.PID)
				break
			}
		}
	}
	return out
}

func (s *jsonStore) AcceptFriendRequest(id int64, fromPID uint64) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return nil, ErrNotFound
	}
	if !hasReqPID(a, fromPID) {
		return nil, ErrNotFound
	}
	removeReqPID(a, fromPID)
	fid, ok := s.byPID[fromPID]
	if !ok {
		_ = s.persist()
		return nil, ErrNotFound
	}
	b := s.Accts[fid]
	addFriendPID(a, b.PID)
	addFriendPID(b, a.PID)
	if err := s.persist(); err != nil {
		return nil, err
	}
	return b, nil
}

func (s *jsonStore) DeclineFriendRequest(id int64, fromPID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	removeReqPID(a, fromPID)
	return s.persist()
}

func (s *jsonStore) RemoveFriend(id int64, friendPID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	removeFriendPID(a, friendPID)
	if fid, ok := s.byPID[friendPID]; ok {
		removeFriendPID(s.Accts[fid], a.PID)
	}
	return s.persist()
}

// BlockUser drops any friendship/pending request with target (both sides) and adds
// target to the caller's block list, so target can no longer friend-request them.
func (s *jsonStore) BlockUser(id int64, targetPID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	if a.PID == targetPID {
		return errors.New("cannot block yourself")
	}
	removeFriendPID(a, targetPID)
	removeReqPID(a, targetPID)
	addBlockedPID(a, targetPID)
	if tid, ok := s.byPID[targetPID]; ok {
		b := s.Accts[tid]
		removeFriendPID(b, a.PID)
		removeReqPID(b, a.PID)
	}
	return s.persist()
}

func (s *jsonStore) UnblockUser(id int64, targetPID uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.Accts[id]
	if !ok {
		return ErrNotFound
	}
	removeBlockedPID(a, targetPID)
	return s.persist()
}

// ---------------------------------------------------------------------------
// Helpers: friend code, validation, session tokens
// ---------------------------------------------------------------------------

func genFriendCode() string {
	for {
		var b [6]byte
		_, _ = rand.Read(b[:])
		n := uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 | uint64(b[4])<<8 | uint64(b[5])
		d := fmt.Sprintf("%012d", n%1_000_000_000_000)
		code := "SW-" + d[0:4] + "-" + d[4:8] + "-" + d[8:12]
		if !banIsCodeBanned(code) { // ne jamais réattribuer un code ami banni
			return code
		}
	}
}

var (
	reUser  = regexp.MustCompile(`^[A-Za-z0-9_\-]{3,16}$`)
	reEmail = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	reDigit = regexp.MustCompile(`[0-9]`)
)

// pwSpecials is the set of characters that count as a "special character" for the
// password policy (kept in sync with the front-end strength meter).
const pwSpecials = "!@#$%^&*()-_=+[]{};:'\",.<>/?\\|`~"

// validatePassword enforces the password policy: >= 8 chars, at least one digit,
// at least one special character. Returns "" if OK, else a user-facing message.
// Used by register, reset and any other password entry so the rule is enforced
// server-side (the front-end meter is UX, this is the guarantee).
func validatePassword(password string) string {
	if len([]rune(password)) < 8 {
		return "Le mot de passe doit faire au moins 8 caractères."
	}
	if !reDigit.MatchString(password) {
		return "Le mot de passe doit contenir au moins un chiffre."
	}
	if !strings.ContainsAny(password, pwSpecials) {
		return "Le mot de passe doit contenir au moins un caractère spécial (! @ # $ % …)."
	}
	return ""
}

func validate(username, email, password string) string {
	if !reUser.MatchString(username) {
		return "Le pseudo doit faire 3 à 16 caractères (lettres, chiffres, _ ou -)."
	}
	if !reEmail.MatchString(email) {
		return "Adresse e-mail invalide."
	}
	return validatePassword(password)
}

// session token = base64(accountID.expiryUnix).hmac — stateless, signed.
var sessionSecret []byte

func loadSecret() {
	if v := os.Getenv("NEXTENDO_SECRET"); v != "" {
		sessionSecret = []byte(v)
		return
	}
	// persist a generated secret next to the data file so tokens survive restarts
	path := "nextendo_secret.key"
	if b, err := os.ReadFile(path); err == nil && len(b) >= 32 {
		sessionSecret, _ = hex.DecodeString(strings.TrimSpace(string(b)))
		if len(sessionSecret) >= 16 {
			return
		}
	}
	sessionSecret = make([]byte, 32)
	_, _ = rand.Read(sessionSecret)
	_ = os.WriteFile(path, []byte(hex.EncodeToString(sessionSecret)), 0o600)
}

// signToken issues a web session token carrying a session id so the session can be
// listed/revoked: base64(accountID.sessionID.expiry).hmac.
func signToken(accountID int64, sessionID string) string {
	payload := fmt.Sprintf("%d.%s.%d", accountID, sessionID, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// signNexToken issues the token the EMULATOR presents to the NEX auth server
// (the game's NEX auth server) in LoginEx. It encodes the account's persistent NEX PID +
// username, signed with the SHARED secret (NEXTENDO_SECRET) so the auth server
// can validate it offline and trust the PID — no DB call needed. Format:
//
//	nx2.<base64url(pid.username.expiry)>.<base64url(hmac)>
//
// The "nx2." prefix lets the auth server recognise a Nextendo token vs the
// legacy stub username.
func signNexToken(pid uint64, username string) string {
	payload := fmt.Sprintf("%d.%s.%d", pid, username, time.Now().Add(30*24*time.Hour).Unix())
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte("nex:" + payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return "nx2." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

// verifyNexToken validates a "nx2." token (issued by signNexToken) and returns the
// account PID. Used so the emulator can authenticate save up/downloads with the
// nex_token it already keeps locally (no separate session token needed).
func verifyNexToken(tok string) (uint64, bool) {
	if !strings.HasPrefix(tok, "nx2.") {
		return 0, false
	}
	parts := strings.SplitN(tok[4:], ".", 2)
	if len(parts) != 2 {
		return 0, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write([]byte("nex:" + string(raw)))
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, false
	}
	fields := strings.SplitN(string(raw), ".", 3) // pid.username.expiry
	if len(fields) != 3 {
		return 0, false
	}
	pid, err := strconv.ParseUint(fields[0], 10, 64)
	if err != nil {
		return 0, false
	}
	exp, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, false
	}
	return pid, true
}

// verifyTokenFull validates a web session token and returns (accountID, sessionID, ok).
// New format = accountID.sessionID.expiry (the session must exist + not be revoked, so a
// revoked browser token dies immediately). Legacy format = accountID.expiry (sessionID="",
// no revocation tracking) — kept valid so pre-session tokens don't break.
func verifyTokenFull(tok string) (int64, string, bool) {
	parts := strings.SplitN(tok, ".", 2)
	if len(parts) != 2 {
		return 0, "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return 0, "", false
	}
	mac := hmac.New(sha256.New, sessionSecret)
	mac.Write(raw)
	want := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(parts[1])) {
		return 0, "", false
	}
	fields := strings.Split(string(raw), ".")
	var idStr, sid, expStr string
	switch len(fields) {
	case 3: // accountID.sessionID.expiry
		idStr, sid, expStr = fields[0], fields[1], fields[2]
	case 2: // legacy accountID.expiry
		idStr, sid, expStr = fields[0], "", fields[1]
	default:
		return 0, "", false
	}
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil {
		return 0, "", false
	}
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return 0, "", false
	}
	if !sessionValid(sid) { // revoked/closed session → the token is dead
		return 0, "", false
	}
	return id, sid, true
}

func verifyToken(tok string) (int64, bool) {
	id, _, ok := verifyTokenFull(tok)
	return id, ok
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

type server struct{ store Store }

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"error": msg})
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if !rateGuard(w, r, rlRegister, "inscription") {
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if !registrationOpen() {
		writeErr(w, http.StatusForbidden, "Les inscriptions sont temporairement fermées, le temps de finaliser la nouvelle version de Nextendo. Reviens bientôt !")
		return
	}
	var in struct{ Username, Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	in.Email = strings.TrimSpace(in.Email)
	if msg := validate(in.Username, in.Email, in.Password); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	if banIsEmailBanned(in.Email) || banIsIPBanned(clientIP(r)) {
		writeErr(w, http.StatusForbidden, "Ce compte a été banni de Nextendo.")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	acct, err := s.store.Create(in.Username, in.Email, string(hash))
	if errors.Is(err, ErrTaken) {
		writeErr(w, http.StatusConflict, "Cette adresse e-mail est déjà utilisée.")
		return
	}
	if err != nil {
		log.Printf("create: %v", err)
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	if ip := clientIP(r); ip != "" {
		_ = s.store.SetRegIP(acct.ID, ip) // réservée si le compte est banni plus tard
	}
	sendVerificationEmail(acct) // e-mail de confirmation (ou lien loggé en mode dev)
	sess := newSession(acct.PID, "browser", clientIP(r), r.UserAgent())
	log.Printf("[register] %s pid=%d code=%s", acct.Username, acct.PID, acct.FriendCode)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     signToken(acct.ID, sess.ID),
		"nex_token": signNexToken(acct.PID, acct.Username),
		"account":   acct.Public(),
	})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	if !rateGuard(w, r, rlLogin, "connexion") {
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct{ Login, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	login := strings.TrimSpace(in.Login)
	// La connexion par pseudo a été retirée : on n'accepte QUE l'e-mail (évite la confusion
	// pseudo-de-compte / nom-affiché-en-jeu, qui peuvent diverger).
	if !reEmail.MatchString(login) {
		writeErr(w, http.StatusUnauthorized, "Connecte-toi avec ton adresse e-mail (la connexion par pseudo a été retirée).")
		return
	}
	acct, err := s.store.ByLogin(login)
	if err != nil || bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "Identifiants incorrects.")
		return
	}
	if acct.Disabled {
		writeErr(w, http.StatusForbidden, "Ce compte est désactivé pour le moment.")
		return
	}
	sess := newSession(acct.PID, "browser", clientIP(r), r.UserAgent())
	log.Printf("[login] %s pid=%d", acct.Username, acct.PID)
	writeJSON(w, http.StatusOK, map[string]any{
		"token":     signToken(acct.ID, sess.ID),
		"nex_token": signNexToken(acct.PID, acct.Username),
		"account":   acct.Public(),
	})
}

// verifyEmail marks the account's e-mail as verified from an e-mailed link
// (GET /api/verify?token=…). The token is stateless and bound to the e-mail, so
// changing the address invalidates any outstanding link. Idempotent.
func (s *server) verifyEmail(w http.ResponseWriter, r *http.Request) {
	tok := r.URL.Query().Get("token")
	id, ok := peekActionTokenID("verify", tok)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Lien de vérification invalide.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Lien de vérification invalide.")
		return
	}
	if _, ok := verifyActionToken("verify", tok, strings.ToLower(acct.Email)); !ok {
		writeErr(w, http.StatusBadRequest, "Lien de vérification invalide ou expiré.")
		return
	}
	if !acct.EmailVerified {
		if err := s.store.SetEmailVerified(acct.ID, true); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		log.Printf("[verify] %s pid=%d e-mail confirmé", acct.Username, acct.PID)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "email": acct.Email, "username": acct.Username})
}

// resendVerification re-sends the verification e-mail to the authenticated account.
func (s *server) resendVerification(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusBadRequest, "Un compte invité n'a pas d'adresse e-mail.")
		return
	}
	if acct.EmailVerified {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "already": true})
		return
	}
	sendVerificationEmail(acct)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// forgot e-mails a password-reset link for the given address. ALWAYS returns 200
// and never reveals whether an account exists (anti-enumeration).
func (s *server) forgot(w http.ResponseWriter, r *http.Request) {
	if !rateGuard(w, r, rlForgot, "mot de passe oublié") {
		return
	}
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct{ Email string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	email := strings.TrimSpace(in.Email)
	if acct, err := s.store.ByLogin(email); err == nil && !acct.IsGuest() {
		sendResetEmail(acct)
		log.Printf("[forgot] réinitialisation demandée pour %s pid=%d", acct.Username, acct.PID)
	} else {
		log.Printf("[forgot] réinitialisation demandée pour un e-mail inconnu (%q) — ignorée", email)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// resetPassword sets a new password from a reset link (POST {token,password}).
// Single-use: the token is bound to the OLD password hash, so it stops verifying
// the instant the password changes.
func (s *server) resetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	var in struct{ Token, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	id, ok := peekActionTokenID("reset", in.Token)
	if !ok {
		writeErr(w, http.StatusBadRequest, "Lien de réinitialisation invalide.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Lien de réinitialisation invalide.")
		return
	}
	if _, ok := verifyActionToken("reset", in.Token, acct.PasswordHash); !ok {
		writeErr(w, http.StatusBadRequest, "Lien invalide ou expiré (il a peut-être déjà été utilisé).")
		return
	}
	if msg := validatePassword(in.Password); msg != "" {
		writeErr(w, http.StatusBadRequest, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	if err := s.store.SetPassword(acct.ID, string(hash)); err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	log.Printf("[reset] %s pid=%d mot de passe réinitialisé", acct.Username, acct.PID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// sessions lists the account's active sessions (navigateur / Ryujinx / Switch) with IP +
// géo, en marquant celle qui fait la requête comme "current".
func (s *server) sessions(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, sid, ok := verifyTokenFull(tok)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Compte introuvable.")
		return
	}
	list := sessionsForPID(acct.PID)
	out := make([]map[string]any, 0, len(list))
	for _, se := range list {
		out = append(out, sessionPublic(se, sid))
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

// revokeSessionHandler révoque UNE session par id (doit appartenir au compte appelant).
func (s *server) revokeSessionHandler(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, _, ok := verifyTokenFull(tok)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Compte introuvable.")
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	target, ok2 := sessionByID(in.ID)
	if !ok2 || target.PID != acct.PID {
		writeErr(w, http.StatusNotFound, "Session introuvable.")
		return
	}
	revokeSession(in.ID)
	log.Printf("[sessions] %s pid=%d a révoqué la session %s (%s)", acct.Username, acct.PID, in.ID, target.Kind)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// revokeAllSessions ferme TOUTES les sessions du compte — y compris le navigateur courant.
func (s *server) revokeAllSessions(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, _, ok := verifyTokenFull(tok)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Compte introuvable.")
		return
	}
	n := revokeAllForPID(acct.PID, "") // "" = on ne garde rien, on ferme aussi le navigateur courant
	log.Printf("[sessions] %s pid=%d a fermé TOUTES les sessions (%d)", acct.Username, acct.PID, n)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "closed": n})
}

// changeEmail met à jour l'adresse e-mail (authentifié, mot de passe requis). La nouvelle
// adresse doit être libre ; le compte redevient NON vérifié + un e-mail de confirmation part.
func (s *server) changeEmail(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	if acct.IsGuest() {
		writeErr(w, http.StatusBadRequest, "Un compte invité n'a pas d'adresse e-mail.")
		return
	}
	var in struct{ Email, Password string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	email := strings.TrimSpace(in.Email)
	if !reEmail.MatchString(email) {
		writeErr(w, http.StatusBadRequest, "Adresse e-mail invalide.")
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "Mot de passe incorrect.")
		return
	}
	if strings.EqualFold(email, acct.Email) {
		writeErr(w, http.StatusBadRequest, "C'est déjà ton adresse e-mail.")
		return
	}
	updated, err := s.store.SetEmail(acct.ID, email)
	if errors.Is(err, ErrTaken) {
		writeErr(w, http.StatusConflict, "Cette adresse e-mail est déjà utilisée.")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	sendVerificationEmail(updated)
	log.Printf("[email-change] pid=%d -> %s (à vérifier)", updated.PID, email)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "account": updated.Public()})
}

// onlineCheck (INTERNAL) is called by the NEX auth servers when a console/emulator logs in to
// play. It enforces the two ONLINE rules and registers the play-session :
//
//	#6 e-mail vérifié OBLIGATOIRE (les guests @nextendo.local sont exemptés) ;
//	#5 un seul endroit à la fois — REFUSE si un AUTRE appareil (Switch vs Ryujinx) joue déjà.
//
// Réponse {allow, reason, where, session_id}. reason ∈ {"unverified","elsewhere",""}.
// evalOnlineGates runs the online gates for a PID and returns ("", true) when the account
// may go online, or (reason, false) with one of: unknown, disabled, unverified,
// discord_unlinked, elsewhere.
//
// It is PURE: no session is created, nothing is written. onlineCheck (the NEX auth path)
// calls it and then mints a session; onlineStatus (the emulator, read-only) calls it to
// learn WHY it was refused so it can show the right message. Keeping the rules in one place
// is what stops the two paths from drifting apart — and a read-only status call must never
// create a session, or merely asking "why was I refused?" would trip the "already playing
// elsewhere" gate against the caller itself.
func (s *server) evalOnlineGates(pid uint64) (string, bool) {
	acct, err := s.store.ByPID(pid)
	if err != nil {
		// PID inconnu = pas un compte Nextendo (ex : NSA brut d'un profil console non lié).
		// RÈGLE : online réservé aux comptes Nextendo -> on REFUSE. Avant, allow=true
		// laissait entrer en « Joueur-XX ». Le jsonStore ne renvoie que ErrNotFound (pas
		// d'erreur transitoire), donc c'est bien « inconnu » et non une panne.
		return "unknown", false
	}
	if acct.Disabled {
		return "disabled", false
	}
	if !acct.EmailVerified && !acct.IsGuest() {
		return "unverified", false
	}
	// Gate Discord : online réservé aux comptes liés au Discord (donc membres du serveur, le bot
	// ne lie qu'un membre). Le lien est poussé ici par le bot (voir discord.go). Piloté par
	// NEXTENDO_REQUIRE_DISCORD=1 pour pouvoir l'activer une fois le backfill des liens confirmé.
	if discordLinkRequired() && acct.DiscordID == "" && !acct.IsGuest() {
		return "discord_unlinked", false
	}
	// #5 un seul endroit à la fois — basé sur la PRÉSENCE RÉELLE (le PID est-il connecté à un
	// serveur de jeu MAINTENANT = visible dans le monitoring). Fini les sessions fantômes :
	// dès qu'il n'apparaît plus dans /api/stats, la place se libère automatiquement.
	if playing, _ := pidPlayingNow(pid); playing {
		return "elsewhere", false
	}
	return "", true
}

// onlineStatus tells the CALLER why its own online login was refused. The emulator hits it
// after a NEX auth rejection so it can show the real reason instead of a generic "servers
// unreachable" — the NEX auth protocol has no field to carry a reason back to the client,
// so without this every gate looked like an outage to the player.
//
// Read-only: it evaluates the same gates but creates no session (see evalOnlineGates).
// Authenticated by the caller's own bearer — session token OR nex token, since the emulator
// only holds the latter — so a caller can only ever ask about itself.
// evalOnlineGatesWithSelf applique les gardes PUIS écarte le faux positif « ailleurs ».
// Un joueur qui se connecte apparaît lui-même dans la présence des serveurs de jeu ; s'y
// fier tel quel le fait se bloquer tout seul. On ne retient « ailleurs » que si un appareil
// de NATURE DIFFÉRENTE (Switch vs Ryujinx) est réellement actif.
//
// ⚠ Les DEUX entrées doivent passer par ici : le serveur de jeu (/internal/online-check) ET
// l'émulateur (/api/online-status). Les avoir divergentes a fait qu'un correctif posé d'un
// seul côté laissait l'autre refuser — c'est ce qu'a révélé la release 1.6.4 de l'émulateur.
func (s *server) evalOnlineGatesWithSelf(pid uint64, kind, ip string) (string, bool) {
	reason, allow := s.evalOnlineGates(pid)
	if !allow && reason == "elsewhere" && activePlayElsewhere(pid, kind, ip) == nil {
		log.Printf("[online-gate] pid=%d : présence détectée mais aucun autre appareil (%s) -> AUTORISÉ", pid, kind)
		return "", true
	}
	return reason, allow
}

func (s *server) onlineStatus(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	// L'appelant est l'émulateur lui-même : sa propre présence ne doit pas le bloquer.
	kind := "ryujinx"
	if se, ok := playSessionForDevice(acct.PID, clientIP(r)); ok && se.Kind != "" {
		kind = se.Kind
	}
	reason, allow := s.evalOnlineGatesWithSelf(acct.PID, kind, clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"allow": allow, "reason": reason})
}

func (s *server) onlineCheck(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		PID  uint64 `json:"pid"`
		Kind string `json:"kind"`
		IP   string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "json invalide")
		return
	}
	if in.Kind == "" {
		in.Kind = "ryujinx"
	}
	reason, allow := s.evalOnlineGatesWithSelf(in.PID, in.Kind, in.IP)
	if !allow {
		log.Printf("[online-check] pid=%d REFUSÉ (%s)", in.PID, reason)
		out := map[string]any{"allow": false, "reason": reason}
		if reason == "elsewhere" {
			out["where"] = "online"
		}
		writeJSON(w, http.StatusOK, out)
		return
	}
	sess := upsertPlaySession(in.PID, in.Kind, in.IP)
	writeJSON(w, http.StatusOK, map[string]any{"allow": true, "session_id": sess.ID})
}

// sessionStatus lets a client (le fork Ryujinx / la Switch) poll whether it should stay
// online : GET /api/session-status (Bearer nex OU session token). Il indique si la session de
// jeu de CET appareil a été révoquée depuis le site (→ popup « reconnecte-toi ») et si l'e-mail
// est vérifié (→ online bloqué). Apparié par PID + l'IP de l'appelant.
func (s *server) sessionStatus(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	revoked := false
	if se, ok := playSessionForDevice(acct.PID, clientIP(r)); ok && se.Revoked {
		revoked = true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"email_verified": acct.EmailVerified || acct.IsGuest(),
		"revoked":        revoked,
	})
}

// nexSession registers/refreshes a CONNECTED session for the calling device. The Ryujinx fork
// heartbeats here while a Nextendo account is linked, so the emulator appears in the account's
// sessions list on the site even before a game is launched. Bearer nex OR web session token.
func (s *server) nexSession(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	sess := upsertDeviceSession(acct.PID, "ryujinx", clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "session_id": sess.ID})
}

// nexToken returns a fresh NEX login token for the authenticated account. The
// Ryujinx "Connexion Nextendo" button (M3) calls this and hands the token to the
// emulator's account/auth layer; the NEX auth server validates it and uses the
// account's persistent PID.
func (s *server) nexToken(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, ok := verifyToken(tok)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Compte introuvable.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"nex_token":   signNexToken(acct.PID, acct.Username),
		"pid":         acct.PID,
		"friend_code": acct.FriendCode,
		"username":    acct.Username,
	})
}

// guest provisions a lightweight online identity with NO email/password — the beta
// "play online without an account" path. It still creates a real account row so the
// guest gets a persistent PID + friend code (online play, friends, presence and save
// sync all work). The client stores the returned token + nex_token locally and that is
// the ONLY credential (there is no password to log back in with); the player can later
// upgrade by registering a full account.
func (s *server) guest(w http.ResponseWriter, r *http.Request) {
	// Mode invité RETIRÉ : il n'existait que pour la beta. Un compte Nextendo est désormais
	// OBLIGATOIRE pour jouer en ligne. L'endpoint répond clairement au cas où un vieux client
	// l'appelle encore.
	writeErr(w, http.StatusGone, "Le mode invité a été retiré. Crée un compte Nextendo sur nextendo.network pour jouer en ligne.")
	return

	//nolint:govet // code invité conservé mais désactivé (voir return ci-dessus)
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "POST attendu")
		return
	}
	if !registrationOpen() {
		writeErr(w, http.StatusForbidden, "Les inscriptions sont temporairement fermées, le temps de finaliser la nouvelle version de Nextendo. Reviens bientôt !")
		return
	}
	ip := clientIP(r)
	if !guestRateAllow(ip) {
		writeErr(w, http.StatusTooManyRequests, "Trop de créations de profil depuis cette adresse. Réessaie plus tard.")
		return
	}
	var in struct{ Username string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !reUser.MatchString(in.Username) {
		writeErr(w, http.StatusBadRequest, "Le pseudo doit faire 3 à 16 caractères (lettres, chiffres, _ ou -).")
		return
	}
	var rnd [12]byte
	_, _ = rand.Read(rnd[:])
	email := "guest-" + hex.EncodeToString(rnd[:]) + "@nextendo.local"
	hash, err := bcrypt.GenerateFromPassword(rnd[:], bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	acct, err := s.store.Create(in.Username, email, string(hash))
	if errors.Is(err, ErrTaken) {
		writeErr(w, http.StatusConflict, "Ce pseudo est déjà pris.")
		return
	}
	if err != nil {
		log.Printf("guest create: %v", err)
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	sess := newSession(acct.PID, "browser", ip, r.UserAgent())
	log.Printf("[guest] %s pid=%d code=%s ip=%s", acct.Username, acct.PID, acct.FriendCode, ip)
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     signToken(acct.ID, sess.ID),
		"nex_token": signNexToken(acct.PID, acct.Username),
		"account":   acct.Public(),
		"guest":     true,
	})
}

// usernameAvailable reports whether a nickname is free, for the guest-profile UI's live
// "available / already taken" feedback. Public, read-only, no account created.
func (s *server) usernameAvailable(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.URL.Query().Get("username"))
	if !reUser.MatchString(name) {
		writeJSON(w, http.StatusOK, map[string]any{"available": false, "reason": "invalid"})
		return
	}
	// Les pseudos ne sont plus uniques (on distingue les joueurs par leur friend code) :
	// tout pseudo au format valide est acceptable.
	writeJSON(w, http.StatusOK, map[string]any{"available": true})
}

// BetaConfig is the remote-control payload the modified Ryujinx polls at startup.
type BetaConfig struct {
	OnlineEnabled  bool   `json:"online_enabled"`
	MinAppVersion  string `json:"min_app_version"`
	MessageEN      string `json:"message_en"`
	MessageFR      string `json:"message_fr"`
	ForceUpdateURL string `json:"force_update_url,omitempty"`
}

// betaConfigFile is the on-disk shape. The top-level fields are the DEFAULT config (served to any
// client whose channel isn't listed). "channels" lets the operator target ONE release channel
// (e.g. "beta") WITHOUT touching others — so disabling the beta never affects a future stable
// version, and untracked test/dev builds (which don't poll this at all) are never affected either.
type betaConfigFile struct {
	BetaConfig
	Channels map[string]BetaConfig `json:"channels,omitempty"`
}

// betaConfigPath is the file loadBetaConfig reads. Overridable via NEXTENDO_BETA_CONFIG so the
// deployed service isn't tied to its working directory (systemd/Docker) — otherwise a CWD
// mismatch would silently bypass the operator's kill-switch.
var betaConfigPath = "beta_config.json"

// loadBetaConfig reads the config on every request so the operator can flip a channel's
// online_enabled / bump its min_app_version with no restart. Returns the channel-specific config
// when present, else the top-level default. A malformed file is logged (not silently ignored).
func loadBetaConfig(channel string) BetaConfig {
	file := betaConfigFile{BetaConfig: BetaConfig{OnlineEnabled: true, MinAppVersion: "0.0.0"}}
	if b, err := os.ReadFile(betaConfigPath); err == nil {
		if err := json.Unmarshal(b, &file); err != nil {
			log.Printf("WARNING: %s is malformed (%v) — serving defaults (online ENABLED)", betaConfigPath, err)
		}
	}
	if channel != "" {
		if c, ok := file.Channels[channel]; ok {
			return c // ONLY this channel is affected
		}
	}
	return file.BetaConfig
}

// guestRateLimiter throttles unauthenticated guest-account creation per client IP (DoS / disk-fill
// guard on /api/guest). Best-effort in-memory sliding window; resets on restart.
var (
	guestRateMu   sync.Mutex
	guestRateHits = map[string][]time.Time{}
)

func guestRateAllow(ip string) bool {
	const window = time.Hour
	const maxPerWindow = 5
	now := time.Now()
	guestRateMu.Lock()
	defer guestRateMu.Unlock()
	kept := guestRateHits[ip][:0]
	for _, t := range guestRateHits[ip] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= maxPerWindow {
		guestRateHits[ip] = kept
		return false
	}
	guestRateHits[ip] = append(kept, now)
	return true
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.IndexByte(xff, ','); i >= 0 {
			return strings.TrimSpace(xff[:i])
		}
		return strings.TrimSpace(xff)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host
}

// betaConfig is the public remote kill-switch / forced-update endpoint. The modified
// client polls it at startup and FAILS CLOSED (blocks online + shows "servers
// unreachable") if it cannot reach it; it blocks online when online_enabled=false or the
// client version < min_app_version.
func (s *server) betaConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, loadBetaConfig(r.URL.Query().Get("channel")))
}

func (s *server) me(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	id, ok := verifyToken(tok)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	acct, err := s.store.ByID(id)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "Compte introuvable.")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": acct.Public()})
}

// profile GETs or PUTs the account's synced in-game identity (nickname / avatar
// / Mii). The emulator pulls it on Nextendo login and pushes it back when the
// local identity changes — so the player's profile + Mii follow the account
// across machines (the "account is authoritative" model).
func (s *server) profile(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r) // session token OR nex token
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		// username = le pseudo AUTORITAIRE du compte (l'émulateur le tire pour resync local)
		writeJSON(w, http.StatusOK, map[string]any{"profile": acct.Profile, "username": acct.Username})
	case http.MethodPut, http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20) // 1 MiB cap (avatar JPEG + Mii)
		var in Profile
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "JSON invalide ou trop volumineux")
			return
		}
		// VALIDATION — ces champs sont resservis à d'AUTRES membres (liste d'amis, demandes
		// d'ami, modale de profil) et finissent dans des attributs src / des styles. Stockés
		// tels quels, ils permettaient d'y glisser du script ou des déclarations CSS et de
		// s'exécuter dans la session de celui qui regarde. On refuse à l'entrée.
		if in.Image != "" && !reB64.MatchString(in.Image) {
			writeErr(w, http.StatusBadRequest, "Image de profil invalide.")
			return
		}
		if in.Color != "" && !reHexColor.MatchString(in.Color) {
			writeErr(w, http.StatusBadRequest, "Couleur invalide.")
			return
		}
		if in.Avatar != "" && !validAvatarRef(in.Avatar) {
			writeErr(w, http.StatusBadRequest, "Avatar invalide.")
			return
		}
		updated, err := s.store.SetProfile(acct.ID, &in)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		log.Printf("[profile] %s pid=%d name=%q mii=%dB image=%dB", updated.Username, updated.PID, in.Name, len(in.Mii), len(in.Image))
		writeJSON(w, http.StatusOK, map[string]any{"profile": updated.Profile})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou PUT attendu")
	}
}

// accountFromBearer resolves the authenticated account from either a web session
// token or the persisted NEX token (nx2.…).
func (s *server) accountFromBearer(r *http.Request) (*Account, bool) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	// Un compte DÉSACTIVÉ garde un jeton valide jusqu'à 30 jours : ne vérifier Disabled
	// qu'à la connexion laissait un compte gelé continuer à utiliser toute l'API (profil,
	// amis, sauvegardes) et à se forger des jetons de jeu. On refuse ici aussi.
	if id, ok := verifyToken(tok); ok {
		if a, err := s.store.ByID(id); err == nil && !a.Disabled {
			return a, true
		}
	}
	if pid, ok := verifyNexToken(tok); ok {
		if a, err := s.store.ByPID(pid); err == nil && !a.Disabled {
			return a, true
		}
	}
	return nil, false
}

// friendView is the public view of a friend (no email/password).
func friendView(a *Account) map[string]any {
	image, avatar, color := "", "", ""
	if a.Profile != nil {
		image = a.Profile.Image
		avatar = a.Profile.Avatar
		color = a.Profile.Color
	}
	v := map[string]any{
		"pid":         a.PID,
		"username":    a.Username,
		"name":        displayName(a), // display pseudo = console nickname (Profile.Name) else username
		"friend_code": a.FriendCode,
		"image":       image,
		"avatar":      avatar, // gallery icon id (fallback pp when no composed image)
		"color":       color,  // pp background color
		"created_at":  a.CreatedAt.Format(time.RFC3339),
	}
	// Real-time presence (status + S2 AppField blob) so the emulator can show the friend
	// ONLINE and JOINABLE in a private battle. Absent/stale -> offline/empty.
	if p, ok := getPresence(a.PID); ok {
		v["presence"] = map[string]any{"status": p.Status, "app_field": p.AppField, "app_id": p.AppID, "app_detail": p.AppDetail}
	} else {
		v["presence"] = map[string]any{"status": 0, "app_field": "", "app_id": "", "app_detail": ""}
	}
	return v
}

// names resolves a comma-separated batch of NEX PIDs to their public pseudo (+ avatar
// image) for the monitoring dashboard. Public info only — no email/token. The NEX PID
// equals the account PID (auth uses account PID), so a player's pseudo is a ByPID lookup.
// GET /api/names?pids=1800000006,1800000007 -> {"names":{"1800000006":{"name":"Kazu","image":"…"}}}
func (s *server) names(w http.ResponseWriter, r *http.Request) {
	out := map[string]map[string]any{}
	for _, p := range strings.Split(r.URL.Query().Get("pids"), ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		pid, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			continue
		}
		if a, err := s.store.ByPID(pid); err == nil {
			// name only — the avatar is a large base64 blob; the dashboard polls every 2s,
			// so we keep the payload lean (real avatars would be a separate URL endpoint).
			out[p] = map[string]any{"name": displayName(a)}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"names": out})
}

// GET /api/nsa?id=<decimal> -> {"pid":N,"name":"…"} — reverse-lookup a real CFW
// Switch's NSA id (its baasUserID as a u64 decimal, which the console presents as
// the LoginEx username) to the owning account PID. The NEX auth uses this so the
// console's NEX PID equals the account PID (stable identity + pseudo) instead of a
// disposable per-login counter. 404 if no account owns that NSA id.
func (s *server) nsa(w http.ResponseWriter, r *http.Request) {
	target, err := strconv.ParseUint(strings.TrimSpace(r.URL.Query().Get("id")), 10, 64)
	if err != nil || target == 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}
	if res, ok := s.store.(interface {
		ByBaasNSA(uint64) (*Account, error)
	}); ok {
		if a, err := res.ByBaasNSA(target); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"pid": a.PID, "name": displayName(a)})
			return
		}
	}
	http.NotFound(w, r)
}

// normalizeFriendCode turns "1234 5678 9012", "123456789012", "SW-1234-5678-9012"
// into the canonical "SW-1234-5678-9012".
func normalizeFriendCode(s string) string {
	digits := make([]rune, 0, 12)
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, r)
		}
	}
	if len(digits) != 12 {
		return strings.ToUpper(strings.TrimSpace(s))
	}
	d := string(digits)
	return "SW-" + d[0:4] + "-" + d[4:8] + "-" + d[8:12]
}

// friends: GET lists the account's friends (with profiles); POST adds one by friend code.
func (s *server) friends(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	switch r.Method {
	case http.MethodGet:
		friends := make([]map[string]any, 0, len(acct.Friends))
		for _, pid := range acct.Friends {
			if f, err := s.store.ByPID(pid); err == nil {
				friends = append(friends, friendView(f))
			} else if rec, ok := banRecordForPID(pid); ok {
				name := rec.Username
				if name == "" {
					name = "Utilisateur banni"
				}
				friends = append(friends, map[string]any{
					"pid": pid, "username": name, "name": name,
					"friend_code": rec.FriendCode, "banned": true,
					"presence": map[string]any{"status": 0},
				})
			}
		}
		requests := make([]map[string]any, 0, len(acct.FriendRequests))
		for _, pid := range acct.FriendRequests {
			if f, err := s.store.ByPID(pid); err == nil {
				requests = append(requests, friendView(f))
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"friends": friends, "requests": requests})
	case http.MethodPost:
		var in struct {
			FriendCode string `json:"friend_code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
			writeErr(w, http.StatusBadRequest, "JSON invalide")
			return
		}
		f, err := s.store.ByFriendCode(normalizeFriendCode(in.FriendCode))
		if err != nil {
			writeErr(w, http.StatusNotFound, "Aucun joueur avec ce friend code.")
			return
		}
		if f.PID == acct.PID {
			writeErr(w, http.StatusBadRequest, "C'est ton propre friend code.")
			return
		}
		target, already, err := s.store.SendFriendRequest(acct.ID, f.PID)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "Impossible d'envoyer la demande.")
			return
		}
		log.Printf("[friends] %s -> %s (already=%v)", acct.Username, target.Username, already)
		writeJSON(w, http.StatusOK, map[string]any{"friend": friendView(target), "already": already})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou POST attendu")
	}
}

// friendAccept: POST {pid} accepts an incoming friend request (becomes mutual).
func (s *server) friendAccept(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct{ PID uint64 }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	b, err := s.store.AcceptFriendRequest(acct.ID, in.PID)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "Demande introuvable.")
		return
	}
	log.Printf("[friends] %s accepted %s", acct.Username, b.Username)
	writeJSON(w, http.StatusOK, map[string]any{"friend": friendView(b)})
}

// friendDecline: POST {pid} declines an incoming friend request.
func (s *server) friendDecline(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct{ PID uint64 }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if err := s.store.DeclineFriendRequest(acct.ID, in.PID); err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// friendRemove: POST {pid} removes a friend (mutual).
func (s *server) friendRemove(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct{ PID uint64 }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if err := s.store.RemoveFriend(acct.ID, in.PID); err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// friendBlock: POST {pid} blocks a user — drops the friendship and prevents them
// from sending future friend requests.
func (s *server) friendBlock(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct{ PID uint64 }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	if err := s.store.BlockUser(acct.ID, in.PID); err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	log.Printf("[friends] %s blocked pid=%d", acct.Username, in.PID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// username: PUT {username} renames the account (the displayed pseudo).
func (s *server) username(w http.ResponseWriter, r *http.Request) {
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}
	var in struct{ Username string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "JSON invalide")
		return
	}
	name := strings.TrimSpace(in.Username)
	if !reUser.MatchString(name) {
		writeErr(w, http.StatusBadRequest, "Pseudo invalide (3 à 16 caractères : lettres, chiffres, _ ou -).")
		return
	}
	a, err := s.store.SetUsername(acct.ID, name)
	if errors.Is(err, ErrTaken) {
		writeErr(w, http.StatusConflict, "Ce pseudo est déjà pris.")
		return
	}
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "erreur interne")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"account": a.Public()})
}

// reTitleID matches a Switch title id (16 hex chars).
var reTitleID = regexp.MustCompile(`^[0-9a-fA-F]{16}$`)

// Validateurs des champs de profil resservis à d'autres membres. Une pp est du base64 pur,
// une couleur un #rrggbb, un avatar soit une composition JSON {bg,char,frame} soit une
// référence de galerie. Tout ce qui sort de ces formes est refusé : c'est par là qu'on
// pouvait injecter du script ou du CSS dans la page de quelqu'un d'autre.
var (
	reB64        = regexp.MustCompile(`^[A-Za-z0-9+/=\s]+$`)
	reHexColor   = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	reAvatarPath = regexp.MustCompile(`^[A-Za-z0-9_./-]+$`)
)

// validAvatarRef accepte les deux formes réellement produites par l'éditeur : une
// composition JSON {bg,char,frame} dont chaque calque est un chemin de galerie, ou une
// référence simple (« img:… » ou un nom de fichier). Une regex seule ne suffisait pas :
// le JSON contient des guillemets, et les interdire cassait les avatars à calques.
func validAvatarRef(s string) bool {
	if s == "" {
		return true
	}
	if s[0] == '{' {
		var layers map[string]string
		if json.Unmarshal([]byte(s), &layers) != nil {
			return false
		}
		for k, v := range layers {
			if k != "bg" && k != "char" && k != "frame" {
				return false
			}
			if v != "" && !reAvatarPath.MatchString(v) {
				return false
			}
		}
		return true
	}
	return reAvatarPath.MatchString(strings.TrimPrefix(s, "img:"))
}

// saveDir holds per-account game-save blobs at saveDir/<pid>/<titleId>.bin.
var saveDir = "saves"

// avatarsDir holds the shared profile-picture GALLERY as avatarsDir/<id>.jpg (256×256 JPEG).
// A user picks one via Profile.Avatar = "<id>"; resolveAvatar() then serves that JPEG as the
// pp on the console / to friends. New icons are dropped here (admin-supplied set).
var avatarsDir = "avatars"

// resolveAvatar returns the base64 JPEG to show as the pp: a directly-uploaded image wins,
// else the referenced gallery icon (Profile.Avatar id) is loaded from avatarsDir, else "".
func resolveAvatar(p *Profile) string {
	if p == nil {
		return ""
	}
	if p.Image != "" {
		return p.Image
	}
	if p.Avatar != "" {
		id := filepath.Base(p.Avatar) // anti path-traversal
		if b, err := os.ReadFile(filepath.Join(avatarsDir, id+".jpg")); err == nil {
			return base64.StdEncoding.EncodeToString(b)
		}
	}
	return ""
}

// avatars lists the gallery icon ids so the site can render a picker. Serving the bytes is
// done by the /avatars/ file server.
func (s *server) avatars(w http.ResponseWriter, r *http.Request) {
	ents, _ := os.ReadDir(avatarsDir)
	ids := []string{}
	for _, e := range ents {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".jpg") {
			ids = append(ids, strings.TrimSuffix(e.Name(), ".jpg"))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"avatars": ids})
}

// internalProfileSync (INTERNAL) reçoit de nx-account un changement que la VRAIE Switch a
// poussé (PATCH /1.0.0/users) : pseudo, Mii, et historique de jeu (playLog). On le persiste
// pour que ça suive le compte -> site + Ryujinx. C'est le sens Switch->serveur.
func (s *server) internalProfileSync(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		PID      uint64 `json:"pid"`
		Nickname string `json:"nickname"`
		Mii      string `json:"mii"`
		PlayLog  string `json:"playLog"`
		Image    string `json:"image"` // pp JPEG base64 uploadée depuis la Switch
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "json invalide")
		return
	}
	acct, err := s.store.ByPID(in.PID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	// pseudo / Mii / pp synchronisés depuis la console -> Profile (tiré par Ryujinx + affiché sur le
	// site). Username reste l'identifiant de connexion : le pseudo console va dans Profile.Name.
	if in.Nickname != "" || in.Mii != "" || in.Image != "" {
		p := acct.Profile
		if p == nil {
			p = &Profile{}
		}
		if in.Nickname != "" {
			p.Name = in.Nickname
		}
		if in.Mii != "" {
			p.Mii = in.Mii
		}
		if in.Image != "" {
			p.Image = in.Image // pp directe (prime sur l'icône galerie)
			p.Avatar = ""      // on bascule sur la photo uploadée
		}
		_, _ = s.store.SetProfile(acct.ID, p)
	}
	// playLog (historique poussé par la console) -> history store {title_id,seconds,last_played}
	if in.PlayLog != "" {
		var pl []struct {
			AppID         string `json:"appInfo:appId"`
			TotalPlayTime int64  `json:"totalPlayTime"` // minutes
			LastPlayedAt  int64  `json:"lastPlayedAt"`  // unix
		}
		if json.Unmarshal([]byte(in.PlayLog), &pl) == nil && len(pl) > 0 {
			entries := make([]historyEntry, 0, len(pl))
			for _, g := range pl {
				if g.AppID == "" {
					continue
				}
				lp := ""
				if g.LastPlayedAt > 0 {
					lp = time.Unix(g.LastPlayedAt, 0).UTC().Format(time.RFC3339)
				}
				entries = append(entries, historyEntry{TitleID: g.AppID, Seconds: g.TotalPlayTime * 60, LastPlayed: lp})
			}
			path := filepath.Join(historyDir, strconv.FormatUint(in.PID, 10)+".json")
			_ = saveHistory(path, mergeHistory(loadHistory(path), entries))
		}
	}
	log.Printf("[profile-sync] pid=%d nick=%q mii=%dB img=%dB playLog=%dB", in.PID, in.Nickname, len(in.Mii), len(in.Image), len(in.PlayLog))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// internalFriendAccept (INTERNAL) applique une acceptation/refus de demande d'ami faite sur la
// Switch au graphe d'amis Nextendo (add mutuel ou refus), pour que ça se reflète site + in-game.
func (s *server) internalFriendAccept(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		PID    uint64 `json:"pid"`
		From   uint64 `json:"from"`
		Accept bool   `json:"accept"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "json invalide")
		return
	}
	acct, err := s.store.ByPID(in.PID)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	if in.Accept {
		_, err = s.store.AcceptFriendRequest(acct.ID, in.From)
	} else {
		err = s.store.DeclineFriendRequest(acct.ID, in.From)
	}
	if err != nil {
		log.Printf("[friend-accept] pid=%d from=%d accept=%v ERR=%v", in.PID, in.From, in.Accept, err)
		writeErr(w, http.StatusInternalServerError, "erreur")
		return
	}
	log.Printf("[friend-accept] pid=%d from=%d accept=%v OK", in.PID, in.From, in.Accept)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// internalResolve (INTERNAL) resolves ANY Nextendo account by friend code
// (?code=8983-6732-7776), BAAS user id (?baas=<16hex or decimal>) or PID (?pid=)
// -> the friend payload nx-account needs to build a BAAS user object. Powers the
// Home-Menu "add friend by code" (GLOBAL directory lookup, not just existing
// friends) and resolving a friend_request's receiver. 404 if no such account.
func (s *server) internalResolve(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	q := r.URL.Query()
	var acct *Account
	err := ErrNotFound
	switch {
	case q.Get("code") != "":
		acct, err = s.store.ByFriendCode(normalizeFriendCode(q.Get("code")))
	case q.Get("pid") != "":
		if pid, e := strconv.ParseUint(q.Get("pid"), 10, 64); e == nil {
			acct, err = s.store.ByPID(pid)
		}
	case q.Get("baas") != "":
		raw := q.Get("baas")
		v, e := strconv.ParseUint(raw, 16, 64)
		if e != nil {
			v, e = strconv.ParseUint(raw, 10, 64)
		}
		if e == nil {
			if res, ok := s.store.(interface {
				ByBaasNSA(uint64) (*Account, error)
			}); ok {
				acct, err = res.ByBaasNSA(v)
			}
		}
	default:
		writeErr(w, http.StatusBadRequest, "code|baas|pid requis")
		return
	}
	if err != nil || acct == nil {
		log.Printf("[resolve] %s -> NON TROUVÉ", r.URL.RawQuery)
		writeJSON(w, http.StatusNotFound, map[string]any{"found": false})
		return
	}
	acct.ensureNintendoIDs()
	avatar := resolveAvatar(acct.Profile)
	log.Printf("[resolve] %s -> pid=%d %q", r.URL.RawQuery, acct.PID, acct.Username)
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": acct.PID, "baasUserID": acct.BaasID, "naID": acct.NaID,
		"nickname": displayName(acct), "friendCode": acct.FriendCode, "avatar": avatar,
		"createdAt": acct.CreatedAt.Unix(), "hasAvatar": avatar != "",
	})
}

// internalFriendRequest (INTERNAL) records a friend request SENT from the console
// (from -> to, by account PID) into the Nextendo friend graph, so it lands in the
// receiver's Home-Menu inbox and reflects on the site / in-game.
func (s *server) internalFriendRequest(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		From uint64 `json:"from"`
		To   uint64 `json:"to"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.From == 0 || in.To == 0 {
		writeErr(w, http.StatusBadRequest, "from/to requis")
		return
	}
	sender, err := s.store.ByPID(in.From)
	if err != nil {
		writeErr(w, http.StatusNotFound, "expéditeur introuvable")
		return
	}
	_, already, err := s.store.SendFriendRequest(sender.ID, in.To)
	if err != nil {
		log.Printf("[friend-request] from=%d to=%d ERR=%v", in.From, in.To, err)
		writeErr(w, http.StatusInternalServerError, "erreur")
		return
	}
	log.Printf("[friend-request] from=%d to=%d already=%v OK", in.From, in.To, already)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "already": already})
}

// sentRequestPIDs derives this account's OUTGOING pending requests (see
// jsonStore.SentRequestPIDs) via the Store, or nil if the store can't.
func (s *server) sentRequestPIDs(pid uint64) []uint64 {
	if sr, ok := s.store.(interface{ SentRequestPIDs(uint64) []uint64 }); ok {
		return sr.SentRequestPIDs(pid)
	}
	return nil
}

// cacheDir holds SHARED shader/PPTC cache archives at cacheDir/<titleId>/{shader,pptc}.zip.
// Unlike saves these are NOT per-account: one set per title (the Nextendo-pinned game
// version), downloaded by anyone to speed up first launch + cut in-game shader stutter.
var cacheDir = "cache_store"

// modsDir holds the curated Mod Store at modsDir/<titleId>/manifest.json + <modId>.zip.
// Only these admin-approved (cosmetic/local) mods are offered in-app, installable per game.
var modsDir = "mods_store"

// bcatDir holds the per-title online schedule (BCAT seed bundle) at bcatDir/<titleId>.zip.
// One per title (e.g. Splatoon 2's VSSetting/Coop/Festival byamls). Public, non-sensitive
// schedule config: NOT bundled in the emulator pack, downloaded into the client's bcat-seed/.
var bcatDir = "bcat_store"

// reModID matches a sanitized mod id (the manifest's id field: letters, digits, underscore).
var reModID = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// save GETs or PUTs a game-save blob for the authenticated account + title. The
// emulator pulls it on game launch (only for Nextendo-compatible titles) and
// pushes it back when the game closes — so progression follows the account.
func (s *server) save(w http.ResponseWriter, r *http.Request) {
	// Accept either a web session token OR the persisted NEX token (nx2.…); both resolve to
	// the account, which is all the per-account save store is keyed by (its PID).
	acct, ok := s.accountFromBearer(r)
	if !ok {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}

	// [Nextendo beta] Cloud saves are a full-account feature — GUEST profiles don't get it.
	if acct.IsGuest() {
		writeErr(w, http.StatusForbidden, "Les sauvegardes dans le cloud ne sont pas disponibles pour les profils invités.")
		return
	}
	pid := acct.PID

	titleID := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/save/"))
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	dir := filepath.Join(saveDir, strconv.FormatUint(pid, 10))
	path := filepath.Join(dir, titleID+".bin")

	switch r.Method {
	case http.MethodGet:
		b, err := os.ReadFile(path)
		if err != nil {
			w.WriteHeader(http.StatusNoContent) // 204 = no save stored yet
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(b)
	case http.MethodPut, http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<20) // 64 MiB cap
		b, err := io.ReadAll(r.Body)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "lecture échouée ou save trop volumineuse")
			return
		}
		// ★ Anti-clobber guard (fixes the recurring save-loss): never let a near-empty /
		// dramatically-smaller save overwrite a real cloud backup. The bug was an EMPTY local
		// save (e.g. MK8DX ~465 B because the wrong/local profile was loaded) being pushed over
		// a good ~MB cloud save, destroying it. If a substantial save already exists and the
		// incoming one is < half its size, REJECT (keep the good one). This self-heals: the empty
		// local just won't clobber the cloud, and the next launch's PULL restores the real save.
		if old, rerr := os.ReadFile(path); rerr == nil && len(old) >= 4096 && len(b) < len(old)/2 {
			log.Printf("[save] pid=%d title=%s REJECTED shrink %dB -> %dB (kept good save)", pid, titleID, len(old), len(b))
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "kept": true, "size": len(old)})
			return
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		// Keep a one-version backup before overwriting, so even a legit shrink is recoverable.
		if old, rerr := os.ReadFile(path); rerr == nil && len(old) > 0 {
			_ = os.WriteFile(path+".bak", old, 0o600)
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0o600); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		log.Printf("[save] pid=%d title=%s %dB", pid, titleID, len(b))
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "size": len(b)})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou PUT attendu")
	}
}

// cache serves the SHARED shader/PPTC archives for a title. Paths:
// bcat serves the per-title online schedule (BCAT seed bundle) as a zip:
//
//	GET /api/bcat/<titleId> -> streams bcatDir/<titleId>.zip (204 if none)
//
// No auth: the schedule is public, non-sensitive config the client needs in its bcat-seed/
// for online to work. (The account gating for actually PLAYING online is enforced elsewhere.)
func (s *server) bcat(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/bcat/")

	// Sous-chemin /cache : bundle NXBC prêt à écrire dans le save delivery-cache BCAT
	// (consommé par le homebrew Nextendo — bcat_cache.go). Toute la logique format+digest est ici.
	if titleID := strings.ToLower(strings.TrimSuffix(rest, "/cache")); strings.HasSuffix(rest, "/cache") {
		if !reTitleID.MatchString(titleID) {
			writeErr(w, http.StatusBadRequest, "titleId invalide")
			return
		}
		bundle, err := buildBcatBundle(titleID)
		if err != nil {
			// "pas de cache pour ce titre" = cas normal (204 muet). Toute AUTRE erreur —
			// chemin refusé (path traversal), trop d'entrées — signale un cache piégé ou
			// corrompu : on le journalise fort plutôt que de l'avaler comme un simple 204.
			if !os.IsNotExist(err) {
				log.Printf("[bcat] titre=%s bundle REFUSÉ : %v", titleID, err)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(len(bundle)))
		// [Audit #6] Même intégrité vérifiable que le canal de MAJ : SHA-256 + signature Ed25519.
		w.Header().Set("X-Nextendo-SHA256", sha256Hex(bundle))
		if sig := signBlob(bundle); sig != "" {
			w.Header().Set("X-Nextendo-Signature", sig)
			w.Header().Set("X-Nextendo-Signature-Alg", "ed25519")
		}
		w.Header().Set("Connection", "close")
		_, _ = w.Write(bundle)
		return
	}

	titleID := strings.ToLower(rest)
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}
	f, err := os.Open(filepath.Join(bcatDir, titleID+".zip"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent) // 204 = nothing published for this title
		return
	}
	defer f.Close()
	w.Header().Set("Content-Type", "application/zip")
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

//	/api/cache/<titleId>/manifest -> JSON {shader:{size},pptc:{size}} (204 if none)
//	/api/cache/<titleId>/shader   -> GET streams shader.zip (204 if none) / PUT stores it
//	/api/cache/<titleId>/pptc     -> GET streams pptc.zip   (204 if none) / PUT stores it
//
// Auth (Bearer session OR nex token) gates the feature to Nextendo users. Archives are
// streamed both ways so the 1.6 GB-class PPTC files never get buffered in memory.
func (s *server) cache(w http.ResponseWriter, r *http.Request) {
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	_, okSession := verifyToken(tok)
	_, okNex := verifyNexToken(tok)
	if !okSession && !okNex {
		writeErr(w, http.StatusUnauthorized, "Session invalide ou expirée.")
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/cache/"), "/", 2)
	if len(parts) != 2 {
		writeErr(w, http.StatusBadRequest, "chemin attendu /api/cache/<titleId>/<manifest|shader|pptc>")
		return
	}
	titleID := strings.ToLower(parts[0])
	kind := parts[1]
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	dir := filepath.Join(cacheDir, titleID)
	shaderPath := filepath.Join(dir, "shader.zip")
	pptcPath := filepath.Join(dir, "pptc.zip")

	if kind == "manifest" {
		m := map[string]any{}
		if fi, err := os.Stat(shaderPath); err == nil {
			m["shader"] = map[string]any{"size": fi.Size()}
		}
		if fi, err := os.Stat(pptcPath); err == nil {
			m["pptc"] = map[string]any{"size": fi.Size()}
		}
		if len(m) == 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, m)
		return
	}

	var path string
	switch kind {
	case "shader":
		path = shaderPath
	case "pptc":
		path = pptcPath
	default:
		writeErr(w, http.StatusBadRequest, "kind invalide (manifest|shader|pptc)")
		return
	}

	switch r.Method {
	case http.MethodGet:
		f, err := os.Open(path)
		if err != nil {
			w.WriteHeader(http.StatusNoContent) // 204 = not seeded yet
			return
		}
		defer f.Close()
		w.Header().Set("Content-Type", "application/zip")
		if fi, err := f.Stat(); err == nil {
			w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
		}
		_, _ = io.Copy(w, f) // stream, never buffer
	case http.MethodPut, http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 4<<30) // 4 GiB cap
		if err := os.MkdirAll(dir, 0o755); err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		tmp := path + ".tmp"
		f, err := os.Create(tmp)
		if err != nil {
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		n, copyErr := io.Copy(f, r.Body)
		f.Close()
		if copyErr != nil {
			os.Remove(tmp)
			writeErr(w, http.StatusBadRequest, "lecture échouée ou archive trop volumineuse")
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			os.Remove(tmp)
			writeErr(w, http.StatusInternalServerError, "erreur interne")
			return
		}
		log.Printf("[cache] title=%s kind=%s %dB", titleID, kind, n)
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "size": n})
	default:
		writeErr(w, http.StatusMethodNotAllowed, "GET ou PUT attendu")
	}
}

// mods serves the curated Mod Store for a title (read-only). Paths:
//
//	/api/mods/<titleId>/manifest -> the manifest.json (list of mods; 204 if none)
//	/api/mods/<titleId>/<modId>  -> streams that mod's zip (204 if absent)
//
// Auth (Bearer) gates it to Nextendo users; the client extracts the zip into the game's
// mod folder. Only admin-curated, cosmetic/local mods live here.
func (s *server) mods(w http.ResponseWriter, r *http.Request) {
	// Require a linked Nextendo account: the Mod Store is reserved to connected players.
	tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	_, okSession := verifyToken(tok)
	_, okNex := verifyNexToken(tok)
	if !okSession && !okNex {
		writeErr(w, http.StatusUnauthorized, "Compte Nextendo requis.")
		return
	}

	parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/api/mods/"), "/", 2)
	if len(parts) != 2 {
		writeErr(w, http.StatusBadRequest, "chemin attendu /api/mods/<titleId>/<manifest|modId>")
		return
	}
	titleID := strings.ToLower(parts[0])
	file := parts[1]
	if !reTitleID.MatchString(titleID) {
		writeErr(w, http.StatusBadRequest, "titleId invalide")
		return
	}

	dir := filepath.Join(modsDir, titleID)

	if file == "manifest" {
		b, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
		if err != nil {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		return
	}

	if !reModID.MatchString(file) {
		writeErr(w, http.StatusBadRequest, "modId invalide")
		return
	}

	f, err := os.Open(filepath.Join(dir, file+".zip"))
	if err != nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/zip")
	if fi, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(fi.Size(), 10))
	}
	_, _ = io.Copy(w, f)
}

// displayName is the pseudo shown EVERYWHERE (console, site, dashboard, friends):
// the console-synced nickname (Profile.Name, pushed via PATCH /1.0.0/users ->
// /internal/profile-sync) if set, else the login Username. Username stays the
// stable login identifier; the console nickname is the display name. Before this,
// the console nickname was persisted to Profile.Name but NOTHING displayed it — so
// changing the pseudo on the console appeared to "not save".
func displayName(a *Account) string {
	if a.Profile != nil && strings.TrimSpace(a.Profile.Name) != "" {
		return a.Profile.Name
	}
	return a.Username
}

// friendList resolves accepted-friend / pending-request PIDs into the payload the
// console's Home-Menu friends API needs. Each entry carries that friend's OWN
// deterministic synthetic BAAS id (derived from its PID), pseudo and friend code —
// so nx-account can build a real BAAS 2.0.0 friend object without a live login.
func (s *server) friendList(pids []uint64) []map[string]any {
	out := []map[string]any{}
	for _, pid := range pids {
		f, err := s.store.ByPID(pid)
		if err != nil {
			continue
		}
		f.ensureNintendoIDs()
		avatar := resolveAvatar(f.Profile)
		// Présence temps-réel (0=Offline,1=Online,2=OnlinePlay) + blob AppField S2 : nx-account
		// s'en sert pour afficher l'ami EN LIGNE dans la liste d'amis de la Switch (au lieu de
		// tout marquer hors ligne). Absente/périmée -> 0 (hors ligne).
		pStatus, pApp, pAppID := 0, "", ""
		if p, ok := getPresence(f.PID); ok {
			pStatus, pApp, pAppID = p.Status, p.AppField, p.AppID
		}
		out = append(out, map[string]any{
			"pid": f.PID, "baasUserID": f.BaasID, "naID": f.NaID,
			"nickname": displayName(f), "friendCode": f.FriendCode, "avatar": avatar,
			"createdAt": f.CreatedAt.Unix(), "hasAvatar": avatar != "",
			"presenceStatus": pStatus, "presenceAppField": pApp, "presenceAppId": pAppID,
		})
	}
	return out
}

// internalIdentity (INTERNAL, co-located with nx-account) returns the user's
// EXISTING Nextendo identity so nx-account surfaces it to a real CFW Switch:
// the real pseudo, profile picture (avatar/Mii) and friend code from this very
// account — NOT a fresh identity — plus the synthetic-but-stable Nintendo ids
// (the hidden "sub" fields the Switch never displays). Logging into your
// Nextendo account on the console brings all your data, like a Nintendo account.
func (s *server) internalIdentity(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	pid, err := strconv.ParseUint(r.URL.Query().Get("pid"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "pid invalide")
		return
	}
	acct, err := s.store.ByPID(pid)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	acct.ensureNintendoIDs() // deterministic; fills in-memory for pre-existing accounts
	nickname := displayName(acct)
	// pseudo affiché = Profile.Name (pseudo synchronisé depuis la console) sinon Username.
	// avatar = image uploadée OU icône de galerie choisie (résolue depuis avatarsDir).
	avatar := resolveAvatar(acct.Profile)
	mii := ""
	if acct.Profile != nil {
		mii = acct.Profile.Mii
	}
	// imageUpdatedAt : bumpé quand le profil (dont la pp) change (SetProfile met UpdatedAt=now).
	// nx-account l'utilise comme thumbnailUploadedAt -> la console voit une date plus récente
	// à son prochain GET users et re-télécharge l'avatar (= la pp se met à jour sur la Switch).
	imageUpdatedAt := int64(1716149960)
	if acct.Profile != nil && !acct.Profile.UpdatedAt.IsZero() {
		imageUpdatedAt = acct.Profile.UpdatedAt.Unix()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": acct.PID, "naID": acct.NaID, "baasUserID": acct.BaasID, "bsDid": acct.BsDid,
		"nickname": nickname, "friendCode": acct.FriendCode, "avatar": avatar, "mii": mii,
		"imageUpdatedAt": imageUpdatedAt,
		"playLog":        historyToPlayLog(acct.PID),
		"friends":        s.friendList(acct.Friends), "friendRequests": s.friendList(acct.FriendRequests),
		"sentRequests": s.friendList(s.sentRequestPIDs(acct.PID)),
	})
}

// internalPIDByBsDid (INTERNAL) résout le « bs:did » que la console présente dans son
// Bearer vers le PID du compte propriétaire. C'est la brique qui permet à nx-account de
// servir la BONNE identité à CHAQUE requête : le bs:did est la seule donnée d'identité
// présente sur tous les appels de la console. Sans ça, nx-account retombait sur une
// variable globale (le dernier compte authentifié) et livrait le compte d'autrui.
// GET /internal/pid-by-bsdid?bsdid=<hex>
func (s *server) internalPIDByBsDid(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	want := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("bsdid")))
	if want == "" {
		writeErr(w, http.StatusBadRequest, "bsdid manquant")
		return
	}
	for _, a := range s.store.AllAccounts() {
		a.ensureNintendoIDs() // déterministe : remplit BsDid pour les comptes anciens
		if strings.ToLower(a.BsDid) == want {
			writeJSON(w, http.StatusOK, map[string]any{"pid": a.PID})
			return
		}
	}
	writeErr(w, http.StatusNotFound, "bs:did inconnu")
}

// internalLogin (INTERNAL) validates Nextendo credentials and returns the same
// identity payload as /internal/identity. nx-account's account-link login page
// posts here so the user signs into THEIR Nextendo account on the console.
func (s *server) internalLogin(w http.ResponseWriter, r *http.Request) {
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		Login    string `json:"login"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil {
		writeErr(w, http.StatusBadRequest, "json invalide")
		return
	}
	acct, err := s.store.ByLogin(strings.TrimSpace(in.Login))
	if err != nil || bcrypt.CompareHashAndPassword([]byte(acct.PasswordHash), []byte(in.Password)) != nil {
		writeErr(w, http.StatusUnauthorized, "identifiants invalides")
		return
	}
	acct.ensureNintendoIDs()
	nickname := displayName(acct)
	// pseudo affiché = Profile.Name (synchronisé depuis la console) sinon Username.
	// avatar = image uploadée OU icône de galerie choisie (résolue depuis avatarsDir).
	avatar := resolveAvatar(acct.Profile)
	mii := ""
	if acct.Profile != nil {
		mii = acct.Profile.Mii
	}
	// imageUpdatedAt : bumpé quand le profil (dont la pp) change (SetProfile met UpdatedAt=now).
	// nx-account l'utilise comme thumbnailUploadedAt -> la console voit une date plus récente
	// à son prochain GET users et re-télécharge l'avatar (= la pp se met à jour sur la Switch).
	imageUpdatedAt := int64(1716149960)
	if acct.Profile != nil && !acct.Profile.UpdatedAt.IsZero() {
		imageUpdatedAt = acct.Profile.UpdatedAt.Unix()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"pid": acct.PID, "naID": acct.NaID, "baasUserID": acct.BaasID, "bsDid": acct.BsDid,
		"nickname": nickname, "friendCode": acct.FriendCode, "avatar": avatar, "mii": mii,
		"imageUpdatedAt": imageUpdatedAt,
		"playLog":        historyToPlayLog(acct.PID),
		"friends":        s.friendList(acct.Friends), "friendRequests": s.friendList(acct.FriendRequests),
		"sentRequests": s.friendList(s.sentRequestPIDs(acct.PID)),
	})
}

// loadEnvFile loads KEY=VALUE lines from nextendo.env (the container's WorkingDir is
// /data, so that's /data/nextendo.env) into the process environment BEFORE the getenv
// reads below. This lets the operator set SMTP credentials — or any NEXTENDO_* var —
// by editing ONE file then `docker restart`, with no container recreation. A real
// environment variable always wins over the file. Path overridable via NEXTENDO_ENV_FILE.
func loadEnvFile() {
	path := os.Getenv("NEXTENDO_ENV_FILE")
	if path == "" {
		path = "nextendo.env"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		k = strings.TrimSpace(k)
		if k == "" || os.Getenv(k) != "" {
			continue // a real env var overrides the file
		}
		_ = os.Setenv(k, strings.Trim(strings.TrimSpace(v), `"'`))
	}
}

func main() {
	loadEnvFile()
	loadSecret()

	if v := os.Getenv("NEXTENDO_SAVES"); v != "" {
		saveDir = v
	}

	if v := os.Getenv("NEXTENDO_CACHE"); v != "" {
		cacheDir = v
	}

	if v := os.Getenv("NEXTENDO_MODS"); v != "" {
		modsDir = v
	}

	if v := os.Getenv("NEXTENDO_BCAT"); v != "" {
		bcatDir = v
	}

	if v := os.Getenv("NEXTENDO_HISTORY"); v != "" {
		historyDir = v
	}

	if v := os.Getenv("NEXTENDO_GAMES"); v != "" {
		gamesDir = v
	}

	if v := os.Getenv("NEXTENDO_AVATARS"); v != "" {
		avatarsDir = v
	}
	_ = os.MkdirAll(avatarsDir, 0o755)

	if v := os.Getenv("NEXTENDO_BETA_CONFIG"); v != "" {
		betaConfigPath = v
	}

	dataPath := os.Getenv("NEXTENDO_DATA")
	if dataPath == "" {
		dataPath = "accounts.json"
	}
	// TODO(M2): if DATABASE_URL is set, use the Postgres store instead.
	store, err := newJSONStore(dataPath)
	if err != nil {
		log.Fatal(err)
	}
	srv := &server{store: store}

// Backfill Nintendo IDs for existing accounts that were created before
// ensureNintendoIDs() was called at creation time. Without this, BaasID
// is empty in accounts.json and ByBaasNSA() re-derives it on the fly
// using the current sessionSecret — which changes on every restart unless
// NEXTENDO_SECRET is set. Real Switch consoles authenticate via baasUserID
// (stored from the first account-link), so after a secret rotation their
// baasUserID no longer matches any account → PID "unknown" → error 2124-3121.
// The emulator is unaffected because it passes the PID directly in the nx2. token.
if js, ok := store.(*jsonStore); ok {
    js.mu.Lock()
    changed := 0
    for _, a := range js.Accts {
        if a.ensureNintendoIDs() {
            changed++
        }
    }
    if changed > 0 {
        if err := js.persist(); err != nil {
            log.Printf("[startup] backfill Nintendo IDs: persist error: %v", err)
        } else {
            log.Printf("[startup] backfill: persisted Nintendo IDs for %d account(s)", changed)
        }
    }
    js.mu.Unlock()
}

	sessionsPath := os.Getenv("NEXTENDO_SESSIONS")
	if sessionsPath == "" {
		sessionsPath = filepath.Join(filepath.Dir(dataPath), "sessions.json")
	}
	loadSessions(sessionsPath)

	applyLaunchFreeze(store) // gel de relance piloté par env (NEXTENDO_LOCKDOWN_KEEP_PID / NEXTENDO_ENABLE_ALL)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/register", srv.register)
	mux.HandleFunc("/api/login", srv.login)
	mux.HandleFunc("/api/verify", srv.verifyEmail)                                                    // confirme l'e-mail (lien reçu par mail)
	mux.HandleFunc("/api/resend-verification", srv.resendVerification)                                // renvoie l'e-mail de confirmation
	mux.HandleFunc("/api/forgot", srv.forgot)                                                         // envoie un lien de réinitialisation
	mux.HandleFunc("/api/reset", srv.resetPassword)                                                   // pose un nouveau mot de passe via le lien
	mux.HandleFunc("/api/email", srv.changeEmail)                                                     // changer l'adresse e-mail (re-vérif)
	mux.HandleFunc("/api/sessions", srv.sessions)                                                     // liste des sessions actives
	mux.HandleFunc("/api/sessions/revoke", srv.revokeSessionHandler)                                  // déconnecter UNE session
	mux.HandleFunc("/api/sessions/revoke-all", srv.revokeAllSessions)                                 // fermer TOUTES les sessions
	mux.HandleFunc("/api/session-status", srv.sessionStatus)                                          // le fork/Switch poll son état online
	mux.HandleFunc("/api/nex-session", srv.nexSession)                                                // heartbeat émulateur → session "connecté" visible sur le site
	mux.HandleFunc("/internal/online-check", internalOnly("/internal/online-check", srv.onlineCheck)) // l'auth NEX : e-mail vérifié + endroit unique
	mux.HandleFunc("/api/online-status", srv.onlineStatus)                                            // l'émulateur : POURQUOI mon online est refusé (lecture seule)
	mux.HandleFunc("/api/online-counts", srv.onlineCounts)                                            // l'émulateur : joueurs en ligne par jeu (liste des jeux)
	mux.HandleFunc("/api/site-config", srv.siteConfig)                                                // état public du site (inscriptions ouvertes/fermées)
	mux.HandleFunc("/api/report", srv.report)                                                         // l'emulateur : signaler un bug (jeton joueur)
	mux.HandleFunc("/api/admin/reports", srv.adminReports)                                            // admin : boite de reception des signalements
	mux.HandleFunc("/api/admin/check", srv.adminCheck)                                                // le front : suis-je admin ?
	mux.HandleFunc("/api/admin/users", srv.adminUsers)                                                // admin : liste des utilisateurs + activité
	mux.HandleFunc("/api/admin/stats", srv.adminStats)                                                // admin : stats globales
	mux.HandleFunc("/api/admin/delete-user", srv.adminDeleteUser)                                     // admin : supprimer un compte
	mux.HandleFunc("/api/admin/ban", srv.adminBan)                                                    // admin/bot : bannir (delete + blocklist + wipe cloud)
	mux.HandleFunc("/api/admin/unban", srv.adminUnban)                                                // admin : lever un ban (libère e-mail/IP/code + débannit du Discord)
	mux.HandleFunc("/api/admin/discord-link", srv.adminDiscordLink)                                   // bot : pousse le lien Discord↔Nextendo (source de vérité du gate)
	mux.HandleFunc("/api/guest", srv.guest)
	mux.HandleFunc("/api/username-available", srv.usernameAvailable)
	mux.HandleFunc("/api/names", srv.names)
	mux.HandleFunc("/api/nsa", srv.nsa)
	mux.HandleFunc("/api/beta-config", srv.betaConfig)
	mux.HandleFunc("/api/me", srv.me)
	mux.HandleFunc("/api/profile", srv.profile)
	mux.HandleFunc("/api/username", srv.username)
	mux.HandleFunc("/api/friends", srv.friends)
	mux.HandleFunc("/api/presence", srv.presence)
	mux.HandleFunc("/internal/presence-batch", internalOnly("/internal/presence-batch", srv.presenceBatch)) // les serveurs de jeu remontent les PID en ligne
	mux.HandleFunc("/api/friends/accept", srv.friendAccept)
	mux.HandleFunc("/api/friends/decline", srv.friendDecline)
	mux.HandleFunc("/api/friends/remove", srv.friendRemove)
	mux.HandleFunc("/api/friends/block", srv.friendBlock)
	mux.HandleFunc("/api/friends/history", srv.friendHistory)
	mux.HandleFunc("/api/save/", srv.save)
	mux.HandleFunc("/api/cache/", srv.cache)
	mux.HandleFunc("/api/bcat/", srv.bcat)
	mux.HandleFunc("/api/nro/", srv.nro)
	mux.HandleFunc("/api/mods/", srv.mods)
	mux.HandleFunc("/api/history", srv.history)
	mux.HandleFunc("/api/gameinfo", srv.gameInfo)
	mux.HandleFunc("/api/gamemedia/", srv.gameMedia)
	mux.HandleFunc("/api/nex-token", srv.nexToken)
	mux.HandleFunc("/api/avatars", srv.avatars) // liste des icônes de la galerie pp
	mux.Handle("/avatars/", http.StripPrefix("/avatars/", http.FileServer(http.Dir(avatarsDir))))
	mux.HandleFunc("/internal/profile-sync", internalOnly("/internal/profile-sync", srv.internalProfileSync))       // nx-account pushes Switch profile/history changes back
	mux.HandleFunc("/internal/friend-accept", internalOnly("/internal/friend-accept", srv.internalFriendAccept))    // nx-account relays Switch friend accept/decline
	mux.HandleFunc("/internal/resolve", internalOnly("/internal/resolve", srv.internalResolve))                     // nx-account resolves a friend code / BAAS id -> account (add-by-code)
	mux.HandleFunc("/internal/friend-request", internalOnly("/internal/friend-request", srv.internalFriendRequest)) // nx-account records a friend request sent from the console
	mux.HandleFunc("/internal/identity", internalOnly("/internal/identity", srv.internalIdentity))                  // nx-account pulls the Nextendo identity for a real CFW Switch
	mux.HandleFunc("/internal/pid-by-bsdid", internalOnly("/internal/pid-by-bsdid", srv.internalPIDByBsDid))        // nx-account résout le bs:did d'une requête -> compte (identité par requête)
	mux.HandleFunc("/internal/login", internalOnly("/internal/login", srv.internalLogin))                           // nx-account's account-link page validates Nextendo credentials here
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, 200, map[string]any{"ok": true}) })

	// L'ancien site marketing servi ici a été RETIRÉ : la racine — et tout chemin non-API —
	// redirige désormais vers le vrai site (nextendo.network). /api/*, /internal/*, /avatars/
	// restent servis (leurs préfixes sont enregistrés AVANT "/"). Override : NEXTENDO_SITE_REDIRECT.
	// NEXTENDO_STATIC branché => on SERT le site localement (test e2e des pages avant
	// déploiement). Sinon, la racine redirige vers la prod comme avant. Ça remet
	// run-site-test.bat en état de marche sans changer le comportement de production.
	if staticDir := os.Getenv("NEXTENDO_STATIC"); staticDir != "" {
		fs := http.FileServer(http.Dir(staticDir))
		mux.Handle("/", spaFallback(staticDir, fs))
		log.Printf("Serving the site locally from %s (NEXTENDO_STATIC set)", staticDir)
	} else {
		siteRedirect := os.Getenv("NEXTENDO_SITE_REDIRECT")
		if siteRedirect == "" {
			siteRedirect = "https://nextendo.network"
		}
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, siteRedirect, http.StatusFound)
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	log.Printf("Nextendo Network account service on http://localhost:%s  (data=%s)", port, dataPath)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// spaFallback serves files from staticDir; missing top-level paths fall back to
// the matching .html (so /register serves register.html) then index.html.
func spaFallback(dir string, fs http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			fs.ServeHTTP(w, r)
			return
		}
		if _, err := os.Stat(filepath.Join(dir, p)); err == nil {
			fs.ServeHTTP(w, r)
			return
		}
		if !strings.Contains(p, ".") {
			if _, err := os.Stat(filepath.Join(dir, p+".html")); err == nil {
				http.ServeFile(w, r, filepath.Join(dir, p+".html"))
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}
