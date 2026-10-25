package native

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// TrophyBackend is np-trophy's private API (openpak/np-trophy). Firmware authentication stays here.
type TrophyBackend struct{ URL, Key string }
type Unlock struct {
	ID       int    `json:"id"`
	EarnedAt int64  `json:"earned_at"`
	Grade    string `json:"grade"`
}
type TrophyGame struct {
	CommunicationID string   `json:"communication_id"`
	Trophies        []Unlock `json:"trophies"`
}

func (b *TrophyBackend) Games(ctx context.Context, account string) ([]TrophyGame, error) {
	return b.Exchange(ctx, account, nil)
}
func (b *TrophyBackend) Exchange(ctx context.Context, account string, payload []byte) ([]TrophyGame, error) {
	if b == nil || b.URL == "" || len(b.Key) < 32 {
		return nil, errors.New("trophy backend not configured")
	}
	method := "GET"
	if payload != nil {
		method = "POST"
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(b.URL, "/")+"/v1/users/"+url.PathEscape(account)+"/trophies", bytes.NewReader(payload))
	if e != nil {
		return nil, e
	}
	req.Header.Set("Authorization", "Bearer "+b.Key)
	client := http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, e := client.Do(req)
	if e != nil {
		return nil, e
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New("trophy backend unavailable")
	}
	var result struct {
		Games []TrophyGame `json:"games"`
	}
	e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&result)
	return result.Games, e
}

func (s *Service) trophyRead(w http.ResponseWriter, r *http.Request) {
	// Native trophy requests carry the same signed login ticket as profile requests.
	id, req, ok := s.identity(w, r)
	if !ok {
		return
	}
	target := id.AccountID
	jid := strings.TrimSpace(req.JID)
	if jid != "" {
		name := strings.SplitN(jid, "@", 2)[0]
		if raw, e := base64.StdEncoding.DecodeString(jid); e == nil && len(raw) >= 16 {
			name = strings.TrimRight(string(raw[:16]), "\x00")
		}
		link, e := s.Core.GetLinkByOnlineID(r.Context(), name)
		if e != nil {
			http.NotFound(w, r)
			return
		}
		if _, e = s.Core.GetAccount(r.Context(), link.AccountID); e != nil {
			http.NotFound(w, r)
			return
		}
		if target != link.AccountID {
			allowed, e := s.Core.CanInteract(r.Context(), id.AccountID, link.AccountID)
			if e != nil || !allowed {
				http.Error(w, "profile unavailable", 403)
				return
			}
		}
		target = link.AccountID
	}
	if s.Trophies == nil {
		http.Error(w, "trophy backend unavailable", 503)
		return
	}
	games, e := s.Trophies.Games(r.Context(), target)
	if e != nil {
		http.Error(w, "trophy backend unavailable", 503)
		return
	}

	countsByGrade := map[string]int{"P": 0, "G": 0, "S": 0, "B": 0}
	for _, game := range games {
		for _, trophy := range game.Trophies {
			if _, known := countsByGrade[trophy.Grade]; !known {
				http.Error(w, "trophy grades unavailable", 503)
				return
			}
			countsByGrade[trophy.Grade]++
		}
	}
	points := countsByGrade["P"]*180 + countsByGrade["G"]*90 + countsByGrade["S"]*30 + countsByGrade["B"]*15
	number, base, next := legacyTrophyLevel(points)
	type level struct {
		Base  string `xml:"base,attr"`
		Next  string `xml:"next,attr"`
		Value string `xml:",chardata"`
	}
	type counts struct {
		Platinum string `xml:"platinum,attr"`
		Gold     string `xml:"gold,attr"`
		Silver   string `xml:"silver,attr"`
		Bronze   string `xml:"bronze,attr"`
	}
	type info struct {
		JID   string `xml:"jid,attr"`
		Point string `xml:"point"`
		Level level  `xml:"level"`
		Types counts `xml:"types"`
	}
	result := struct {
		XMLName xml.Name `xml:"nptrophy"`
		Result  string   `xml:"result,attr"`
		List    struct {
			Info []info `xml:"info"`
		} `xml:"list"`
	}{Result: "00"}
	if strings.HasSuffix(r.URL.Path, "get_multi_user_info_privacy") {
		result.List.Info = []info{{JID: jid, Point: strconv.Itoa(points), Level: level{strconv.Itoa(base), strconv.Itoa(next), strconv.Itoa(number)}, Types: counts{strconv.Itoa(countsByGrade["P"]), strconv.Itoa(countsByGrade["G"]), strconv.Itoa(countsByGrade["S"]), strconv.Itoa(countsByGrade["B"])}}}
	}
	xmlReply(w, "nptrophy", result)
}

// Firmware 4.93 exposes the original PS3 level scale. See docs/provenance.md.
func legacyTrophyLevel(points int) (number, base, next int) {
	thresholds := []int{0, 200, 600, 1200, 2400, 4000, 6000, 8000, 10000, 12000, 14000, 16000}
	for i := 0; i < len(thresholds)-1; i++ {
		if points < thresholds[i+1] {
			return i + 1, thresholds[i], thresholds[i+1]
		}
	}
	n := (points - 16000) / 8000
	return 12 + n, 16000 + n*8000, 24000 + n*8000
}

type nativeTrophyList struct {
	Info []nativeTrophyInfo `xml:"info"`
}
type nativeTrophyInfo struct {
	NPCommID    string `xml:"npcommid,attr"`
	LastUpdated string `xml:"last-updated,omitempty"`
	Trophies    struct {
		Entries []nativeTrophy `xml:"trophy"`
	} `xml:"trophies"`
}
type nativeTrophy struct {
	ID        string `xml:"id,attr"`
	Type      string `xml:"type,attr"`
	Timestamp string `xml:",chardata"`
}

var trophyCommunicationID = regexp.MustCompile(`^[A-Z0-9]{9}_[0-9]{2}$`)

func (s *Service) trophySync(w http.ResponseWriter, r *http.Request) {
	id, req, ok := s.identity(w, r)
	if !ok {
		return
	}
	if req.XMLName.Local != "nptrophy" || len(req.TrophyList.Info) > 64 {
		http.Error(w, "invalid trophy request", 400)
		return
	}
	result := struct {
		XMLName xml.Name         `xml:"nptrophy"`
		Result  string           `xml:"result,attr"`
		List    nativeTrophyList `xml:"list"`
	}{Result: "00"}
	for _, set := range req.TrophyList.Info {
		if !trophyCommunicationID.MatchString(set.NPCommID) || len(set.Trophies.Entries) > 1024 {
			http.Error(w, "invalid trophy set", 400)
			return
		}
		entries := []map[string]any{}
		for _, t := range set.Trophies.Entries {
			wireID, e := strconv.Atoi(t.ID)
			if e != nil || wireID < 1 || wireID > 1024 {
				http.Error(w, "invalid trophy ID", 400)
				return
			}
			grades := map[string]string{"0": "B", "1": "S", "2": "G", "3": "P"}
			grade, ok := grades[t.Type]
			if !ok {
				http.Error(w, "invalid trophy grade", 400)
				return
			}
			stamp, e := time.Parse(time.RFC3339Nano, strings.TrimSpace(t.Timestamp))
			if e != nil || stamp.Unix() < 0 {
				http.Error(w, "invalid trophy timestamp", 400)
				return
			}
			entries = append(entries, map[string]any{"id": wireID - 1, "earned_at": stamp.Unix(), "grade": grade})
		}
		payload, _ := json.Marshal(map[string]any{"communication_id": set.NPCommID, "trophies": entries})
		if s.Trophies == nil {
			http.Error(w, "trophy backend unavailable", 503)
			return
		}
		games, e := s.Trophies.Exchange(r.Context(), id.AccountID, payload)
		if e != nil {
			http.Error(w, "trophy backend unavailable", 503)
			return
		}
		answer := nativeTrophyInfo{NPCommID: set.NPCommID, LastUpdated: time.Now().UTC().Format(time.RFC3339)}
		for _, game := range games {
			if game.CommunicationID == set.NPCommID {
				for _, t := range game.Trophies {
					types := map[string]string{"B": "0", "S": "1", "G": "2", "P": "3"}
					kind, known := types[t.Grade]
					if !known {
						http.Error(w, "trophy grades unavailable", 503)
						return
					}
					answer.Trophies.Entries = append(answer.Trophies.Entries, nativeTrophy{strconv.Itoa(t.ID + 1), kind, time.Unix(t.EarnedAt, 0).UTC().Format(time.RFC3339)})
				}
			}
		}
		result.List.Info = append(result.List.Info, answer)
	}
	xmlReply(w, "nptrophy", result)
}
