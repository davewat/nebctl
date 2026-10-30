package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"
)

// The console can hold the CA key for a machine whose ca.key is kept
// offline. It lives only in this process's memory: it goes to the machine on
// nebctl's stdin for each signing, and is wiped caKeyTTL after its last use,
// on Forget, when the machine is disconnected, or when the console stops.

const caKeyTTL = 15 * time.Minute

type heldKey struct {
	key, passphrase []byte
	until           time.Time
	timer           *time.Timer
}

func (h *heldKey) wipe() {
	clear(h.key)
	clear(h.passphrase)
	h.timer.Stop()
}

func (c *console) holdKey(id string, in caKeyInput) time.Time {
	h := &heldKey{key: []byte(in.Key), passphrase: []byte(in.Passphrase), until: time.Now().Add(caKeyTTL)}
	h.timer = time.AfterFunc(caKeyTTL, func() { c.expireKey(id, h) })
	c.mu.Lock()
	old := c.caKeys[id]
	c.caKeys[id] = h
	c.mu.Unlock()
	if old != nil {
		old.wipe()
	}
	return h.until
}

func (c *console) expireKey(id string, h *heldKey) {
	c.mu.Lock()
	if c.caKeys[id] == h && time.Now().After(h.until) {
		delete(c.caKeys, id)
	} else {
		h = nil // replaced, or used since the timer was set
	}
	c.mu.Unlock()
	if h != nil {
		h.wipe()
	}
}

func (c *console) forgetKey(id string) {
	c.mu.Lock()
	h := c.caKeys[id]
	delete(c.caKeys, id)
	c.mu.Unlock()
	if h != nil {
		h.wipe()
	}
}

// useKey returns the held key as nebctl's stdin and restarts its clock, or
// nil when none is held.
func (c *console) useKey(id string) []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.caKeys[id]
	if h == nil {
		return nil
	}
	h.until = time.Now().Add(caKeyTTL)
	h.timer.Reset(caKeyTTL)
	data, _ := json.Marshal(caKeyInput{Key: string(h.key), Passphrase: string(h.passphrase)})
	return data
}

func (c *console) keyHeldUntil(id string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if h := c.caKeys[id]; h != nil {
		return h.until, true
	}
	return time.Time{}, false
}

type callFunc func(pattern string, build func(r *http.Request) (appCall, error), after func(r *http.Request, v map[string]any))

func (c *console) caKeyRoutes(m *http.ServeMux, call callFunc) {
	// pasted reads {key, passphrase} and runs cmd there with it on stdin;
	// once cmd accepts it, the console holds it.
	pasted := func(cmd string) {
		call("POST /api/t/{t}/ca-key/"+cmd, func(r *http.Request) (appCall, error) {
			var in caKeyInput
			if err := body(r, &in); err != nil {
				return appCall{}, err
			}
			if err := checkCAKeyText(in.Key); err != nil {
				return appCall{}, err
			}
			data, err := json.Marshal(in)
			id := r.PathValue("t")
			return appCall{
				args:  []string{"ca-key-" + cmd, "-ca-key-stdin"},
				input: data,
				onOK:  func(v map[string]any) { v["caKeyHeldUntil"] = c.holdKey(id, in) },
			}, err
		}, nil)
	}
	pasted("check")
	pasted("remove")
	call("GET /api/t/{t}/ca-key/file", func(*http.Request) (appCall, error) {
		return appCall{args: []string{"ca-key-show"}}, nil
	}, nil)
	m.HandleFunc("DELETE /api/t/{t}/ca-key", c.forgetKeyHandler)
}

func (c *console) forgetKeyHandler(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("t")
	if _, ok := c.keyHeldUntil(id); !ok {
		writeErr(w, http.StatusNotFound, errors.New("no CA key is held for that machine"))
		return
	}
	c.forgetKey(id)
	writeJSON(w, http.StatusOK, map[string]string{"message": "The console forgot the CA key"})
}
