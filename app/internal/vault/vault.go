// Package vault stores items encrypted with a random data key that the master password wraps.
package vault

import (
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"
)

const formatVersion = 1

var (
	ErrNotInitialized     = errors.New("vault: not initialized")
	ErrAlreadyInitialized = errors.New("vault: already initialized")
	ErrLocked             = errors.New("vault: locked")
	ErrWrongPassword      = errors.New("vault: wrong master password")
	ErrNotFound           = errors.New("vault: item not found")
	ErrUnsupportedFormat  = errors.New("vault: file was written by a newer or unknown version")
	ErrCorrupt            = errors.New("vault: data failed integrity check")
)

// Settings are encrypted with the data key so they cannot be changed without unlocking.
type Settings struct {
	IdleMinutes   int        `json:"idleMinutes"`
	Changes       int64      `json:"changes"`       // bumped with every item change, in the same transaction
	BackupChanges int64      `json:"backupChanges"` // Changes when the last verified backup was written
	BackupAt      int64      `json:"backupAt"`
	BackupCount   int        `json:"backupCount"`
	AIClients     []AIClient `json:"aiClients,omitempty"`
}

// AIClient is a paired AI tool. Only a hash of its token is kept.
type AIClient struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	TokenHash []byte `json:"tokenHash"`
	Created   int64  `json:"created"`
}

// BackupStale reports whether items changed since the last backup (or none was made).
func (s Settings) BackupStale() bool { return s.BackupAt == 0 || s.Changes != s.BackupChanges }

// Vault is safe for concurrent use.
type Vault struct {
	mu       sync.Mutex
	st       *store
	id       string
	dek      []byte
	items    map[string]*Item
	settings Settings
	now      func() time.Time
}

// Open opens or creates the vault file. It starts locked.
func Open(path string) (*Vault, error) {
	st, err := openStore(path)
	if err != nil {
		return nil, err
	}
	v := &Vault{st: st, now: time.Now}
	if raw, ok, err := st.meta("format"); err != nil {
		st.close()
		return nil, err
	} else if ok {
		n, err := strconv.Atoi(string(raw))
		if err != nil || n != formatVersion {
			st.close()
			return nil, ErrUnsupportedFormat
		}
		id, _, err := st.meta("vault_id")
		if err != nil {
			st.close()
			return nil, err
		}
		v.id = string(id)
	}
	return v, nil
}

func (v *Vault) Close() error {
	v.Lock()
	return v.st.close()
}

func (v *Vault) Initialized() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.id != ""
}

func (v *Vault) Locked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.dek == nil
}

// The "passpw/" labels come from the project's old name (PASS_PW). They are bound into existing
// vaults and backups, so they must never change.
func dekAAD(vaultID string) []byte      { return []byte("passpw/dek/v1|" + vaultID) }
func settingsAAD(vaultID string) []byte { return []byte("passpw/settings/v1|" + vaultID) }
func itemAAD(vaultID, itemID string, rev int64) []byte {
	return []byte(fmt.Sprintf("passpw/item/v1|%s|%s|%d", vaultID, itemID, rev))
}

// Create sets up a new vault and leaves it unlocked.
func (v *Vault) Create(master []byte) error {
	return v.create(master, nil, Settings{IdleMinutes: 5})
}

// create writes a fresh vault (new ID and data key) holding items, in one transaction. Caller does not hold v.mu.
func (v *Vault) create(master []byte, items []Item, settings Settings) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.id != "" {
		return ErrAlreadyInitialized
	}
	id := hex.EncodeToString(randomBytes(16))
	dek := randomBytes(keyLen)
	wrapped, kdf, salt, err := wrapDEK(master, dek, id, DefaultKDF)
	if err != nil {
		return err
	}
	sealedSettings, err := sealJSON(dek, settings, settingsAAD(id))
	if err != nil {
		return err
	}
	mem := make(map[string]*Item, len(items))
	rows := make([]rawItem, 0, len(items))
	for _, it := range items {
		it := it
		it.Revision = 1 // ciphertext is bound to this vault, so revisions restart
		blob, err := sealJSON(dek, it, itemAAD(id, it.ID, it.Revision))
		if err != nil {
			return err
		}
		rows = append(rows, rawItem{it.ID, it.Revision, blob})
		mem[it.ID] = &it
	}
	err = v.st.tx(func(tx *sql.Tx) error {
		for k, val := range map[string][]byte{
			"format": []byte(strconv.Itoa(formatVersion)), "vault_id": []byte(id),
			"kdf": kdf, "salt": salt, "wrapped_dek": wrapped, "settings": sealedSettings,
		} {
			if err := setMeta(tx, k, val); err != nil {
				return err
			}
		}
		for _, r := range rows {
			if err := putItem(tx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	v.id, v.dek, v.items, v.settings = id, dek, mem, settings
	return nil
}

// bumpChanges records an item change inside tx. Caller holds v.mu and applies next on success.
func (v *Vault) bumpChanges(tx *sql.Tx) (Settings, error) {
	next := v.settings
	next.Changes++
	raw, err := sealJSON(v.dek, next, settingsAAD(v.id))
	if err != nil {
		return next, err
	}
	return next, setMeta(tx, "settings", raw)
}

func wrapDEK(master, dek []byte, vaultID string, p KDFParams) (wrapped, kdfJSON, salt []byte, err error) {
	salt = randomBytes(saltLen)
	kek := deriveKey(master, salt, p)
	defer wipe(kek)
	wrapped, err = seal(kek, dek, dekAAD(vaultID))
	if err != nil {
		return nil, nil, nil, err
	}
	kdfJSON, err = json.Marshal(p)
	return wrapped, kdfJSON, salt, err
}

// unwrapDEK returns the data key or ErrWrongPassword. Caller holds v.mu.
func (v *Vault) unwrapDEK(master []byte) ([]byte, error) {
	if v.id == "" {
		return nil, ErrNotInitialized
	}
	kdfJSON, ok1, err1 := v.st.meta("kdf")
	salt, ok2, err2 := v.st.meta("salt")
	wrapped, ok3, err3 := v.st.meta("wrapped_dek")
	if err := errors.Join(err1, err2, err3); err != nil {
		return nil, err
	}
	if !ok1 || !ok2 || !ok3 || len(salt) != saltLen {
		return nil, ErrCorrupt
	}
	var p KDFParams
	if err := json.Unmarshal(kdfJSON, &p); err != nil {
		return nil, ErrCorrupt
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	kek := deriveKey(master, salt, p)
	defer wipe(kek)
	dek, err := open(kek, wrapped, dekAAD(v.id))
	if err != nil {
		return nil, ErrWrongPassword
	}
	return dek, nil
}

// Unlock decrypts the data key and all items into memory.
func (v *Vault) Unlock(master []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dek, err := v.unwrapDEK(master)
	if err != nil {
		return err
	}
	items, settings, err := v.load(dek)
	if err != nil {
		wipe(dek)
		return err
	}
	v.dek, v.items, v.settings = dek, items, settings
	return nil
}

func (v *Vault) load(dek []byte) (map[string]*Item, Settings, error) {
	var settings Settings
	if raw, ok, err := v.st.meta("settings"); err != nil {
		return nil, settings, err
	} else if ok {
		if err := openJSON(dek, raw, settingsAAD(v.id), &settings); err != nil {
			return nil, settings, ErrCorrupt
		}
	}
	rows, err := v.st.items()
	if err != nil {
		return nil, settings, err
	}
	items := make(map[string]*Item, len(rows))
	for _, r := range rows {
		var it Item
		if err := openJSON(dek, r.blob, itemAAD(v.id, r.id, r.revision), &it); err != nil {
			return nil, settings, fmt.Errorf("%w (item %s)", ErrCorrupt, r.id)
		}
		it.ID, it.Revision = r.id, r.revision
		items[r.id] = &it
	}
	return items, settings, nil
}

// Lock forgets the data key and every decrypted value.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek != nil {
		wipe(v.dek)
	}
	v.dek, v.items = nil, nil
}

// VerifyMaster checks the master password without changing state.
func (v *Vault) VerifyMaster(master []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dek, err := v.unwrapDEK(master)
	if err != nil {
		return err
	}
	ok := v.dek == nil || subtle.ConstantTimeCompare(dek, v.dek) == 1
	wipe(dek)
	if !ok {
		return ErrCorrupt
	}
	return nil
}

// ChangeMaster re-wraps the data key; item ciphertext is untouched.
func (v *Vault) ChangeMaster(oldPw, newPw []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	dek, err := v.unwrapDEK(oldPw)
	if err != nil {
		return err
	}
	defer wipe(dek)
	wrapped, kdf, salt, err := wrapDEK(newPw, dek, v.id, DefaultKDF)
	if err != nil {
		return err
	}
	return v.st.tx(func(tx *sql.Tx) error {
		return errors.Join(setMeta(tx, "kdf", kdf), setMeta(tx, "salt", salt), setMeta(tx, "wrapped_dek", wrapped))
	})
}

// Items returns copies sorted by name.
func (v *Vault) Items() ([]Item, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return nil, ErrLocked
	}
	out := make([]Item, 0, len(v.items))
	for _, it := range v.items {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (v *Vault) Item(id string) (Item, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return Item{}, ErrLocked
	}
	it, ok := v.items[id]
	if !ok {
		return Item{}, ErrNotFound
	}
	return *it, nil
}

// Save inserts (empty ID) or updates an item. An empty password or note on update keeps the old secret.
func (v *Vault) Save(in Item) (Item, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return Item{}, ErrLocked
	}
	now := v.now().Unix()
	it := in
	if in.ID == "" {
		it.ID = hex.EncodeToString(randomBytes(16))
		it.Revision, it.Created = 1, now
	} else {
		old, ok := v.items[in.ID]
		if !ok {
			return Item{}, ErrNotFound
		}
		it.Type, it.Created, it.Revision = old.Type, old.Created, old.Revision+1
		if it.Type == TypeNote && it.Note == "" {
			it.Note = old.Note
		}
		if it.Type != TypeNote && it.Password == "" {
			it.Password = old.Password
		}
	}
	it.Updated = now
	if err := normalize(&it); err != nil {
		return Item{}, err
	}
	blob, err := sealJSON(v.dek, it, itemAAD(v.id, it.ID, it.Revision))
	if err != nil {
		return Item{}, err
	}
	var next Settings
	if err := v.st.tx(func(tx *sql.Tx) (err error) {
		if err = putItem(tx, rawItem{it.ID, it.Revision, blob}); err != nil {
			return err
		}
		next, err = v.bumpChanges(tx)
		return err
	}); err != nil {
		return Item{}, err
	}
	v.settings = next
	stored := it
	v.items[it.ID] = &stored
	return it, nil
}

func (v *Vault) Delete(id string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	if _, ok := v.items[id]; !ok {
		return ErrNotFound
	}
	var next Settings
	if err := v.st.tx(func(tx *sql.Tx) (err error) {
		if err = deleteItem(tx, id); err != nil {
			return err
		}
		next, err = v.bumpChanges(tx)
		return err
	}); err != nil {
		return err
	}
	v.settings = next
	delete(v.items, id)
	return nil
}

func (v *Vault) Settings() (Settings, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return Settings{}, ErrLocked
	}
	return v.settings, nil
}

// UpdateSettings applies change to the current settings and saves them atomically.
func (v *Vault) UpdateSettings(change func(*Settings)) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.dek == nil {
		return ErrLocked
	}
	s := v.settings
	change(&s)
	raw, err := sealJSON(v.dek, s, settingsAAD(v.id))
	if err != nil {
		return err
	}
	if err := v.st.tx(func(tx *sql.Tx) error { return setMeta(tx, "settings", raw) }); err != nil {
		return err
	}
	v.settings = s
	return nil
}

func sealJSON(key []byte, value any, aad []byte) ([]byte, error) {
	plain, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	defer wipe(plain)
	return seal(key, plain, aad)
}

func openJSON(key, ciphertext, aad []byte, out any) error {
	plain, err := open(key, ciphertext, aad)
	if err != nil {
		return err
	}
	defer wipe(plain)
	return json.Unmarshal(plain, out)
}
