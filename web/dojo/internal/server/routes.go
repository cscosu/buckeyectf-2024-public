package server

import (
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/go-chi/jwtauth/v5"
	"github.com/gorilla/websocket"
)

var TokenAuth *jwtauth.JWTAuth

const MaxBossHealth = 1000

type GameState struct {
	id           int32
	bossHealth   int32
	playerHealth int32
	plundered    int32
	lastDodge    time.Time

	conn *websocket.Conn
}

func (gs *GameState) SyncJSON() {
	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]interface{}{
			"action":       "sync",
			"playerHealth": gs.playerHealth,
			"bossHealth":   gs.bossHealth,
		})
	}

	if gs.bossHealth <= 0 {
		if gs.conn != nil {
			gs.conn.WriteJSON(map[string]string{"action": "win"})

			if gs.plundered > 800 {
				flag, exists := os.LookupEnv("FLAG")
				if !exists {
					flag = "bctf{fake_flag}"
				}
				gs.conn.WriteJSON(map[string]string{"flag": flag})
			}

			gs.conn.Close()
		}

		delete(gameStates, gs.id)
	}

	if gs.playerHealth <= 0 {
		if gs.conn != nil {
			gs.conn.WriteJSON(map[string]string{"action": "lose", "reason": "died"})
			gs.conn.Close()
		}
		delete(gameStates, gs.id)
	}
}

func (gs *GameState) PlayerAttack() (success bool, amount int32) {
	if gs.lastDodge.Add(1 * time.Second).After(time.Now()) {
		return false, 0
	}

	amt := int32(rand.IntN(12) + 2)

	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]interface{}{"action": "player_attack", "amount": amt})
	}

	gs.bossHealth -= amt
	gs.SyncJSON()
	return true, amt
}

func (gs *GameState) PlayerDodge() {
	gs.lastDodge = time.Now()
}

func (gs *GameState) PlayerPlunder() (bool, int32) {
	if gs.lastDodge.Add(1 * time.Second).After(time.Now()) {
		return false, 0
	}

	amount := int32(rand.IntN(12) + 2)
	gs.plundered += amount
	return true, amount
}

func (gs *GameState) BossAttack(amount int32) {
	if gs.lastDodge.Add(1 * time.Second).After(time.Now()) {
		if gs.conn != nil {
			gs.conn.WriteJSON(map[string]interface{}{"action": "dodged", "amount": amount})
		}
		return
	}

	gs.playerHealth -= amount

	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]interface{}{"action": "boss_attack", "amount": amount})
	}
	gs.SyncJSON()
}

func (gs *GameState) BossSignalAttack() {
	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]interface{}{"action": "signal"})
	}
}

func (gs *GameState) BossHeal(amount int32) {
	gs.bossHealth = min(gs.bossHealth+amount, MaxBossHealth)

	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]interface{}{"action": "heal", "amount": amount})
	}
	gs.SyncJSON()
}

func (gs *GameState) TimeoutLose() {
	if gs.conn != nil {
		gs.conn.WriteJSON(map[string]string{"action": "lose", "reason": "timed out"})
		gs.conn.Close()
	}
	delete(gameStates, gs.id)
}

var gameStates = make(map[int32]*GameState)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin:     func(r *http.Request) bool { return os.Getenv("BF_PRODUCTION") != "true" },
}

func (s *Server) RegisterRoutes() http.Handler {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Get("/", s.FrontendHandler)
	r.Get("/*", s.FrontendHandler)

	r.Group(func(r chi.Router) {
		r.Use(middleware.Logger)
		r.Use(middleware.Timeout(time.Second * 60))
		r.Use(httprate.LimitByRealIP(2, time.Second))
		r.Get("/api/new", s.NewGameHandler)

		r.Group(func(r chi.Router) {
			r.Use(jwtauth.Verifier(TokenAuth))
			r.Use(jwtauth.Authenticator(TokenAuth))

			r.Get("/api/attack", s.AttackHandler)
			r.Get("/api/dodge", s.DodgeHandler)
			r.Get("/api/plunder", s.PlunderHandler)
			r.Get("/api/ws", s.WebsocketHandler)
		})
	})

	return r
}

func (s *Server) FrontendHandler(w http.ResponseWriter, r *http.Request) {
	ext := filepath.Ext(r.URL.Path)

	// If there is no file extension, and it does not end with a slash,
	// assume it's an HTML file and append .html
	if ext == "" && !strings.HasSuffix(r.URL.Path, "/") {
		r.URL.Path += ".html"
	}

	http.FileServer(http.Dir("frontend/build")).ServeHTTP(w, r)
}

func (s *Server) AttackHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	game_id := int32(claims["game_id"].(float64))

	gameState := gameStates[game_id]
	if gameState == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Game not found"})
		return
	}

	success, amount := gameState.PlayerAttack()
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "You can't attack right now"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success", "amount": amount})
}

func (s *Server) DodgeHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	game_id := int32(claims["game_id"].(float64))

	gameState := gameStates[game_id]
	if gameState == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Game not found"})
		return
	}

	gameState.PlayerDodge()

	json.NewEncoder(w).Encode(map[string]interface{}{"status": "success"})
}

func (s *Server) PlunderHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	game_id := int32(claims["game_id"].(float64))

	gameState := gameStates[game_id]
	if gameState == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Game not found"})
		return
	}

	success, amount := gameState.PlayerPlunder()
	if !success {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "You can't plunder right now"})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": "success",
		"amount": amount,
		"total":  gameState.plundered,
	})
}

func (s *Server) NewGameHandler(w http.ResponseWriter, r *http.Request) {
	gameId := rand.Int32()
	_, tokenString, _ := TokenAuth.Encode(map[string]interface{}{"game_id": gameId})

	gameStates[gameId] = &GameState{
		id:           gameId,
		bossHealth:   MaxBossHealth,
		playerHealth: 100,
	}

	cookie := http.Cookie{
		Name:     "jwt",
		Value:    tokenString,
		HttpOnly: false,
	}

	http.SetCookie(w, &cookie)

	go gameRunner(gameId)

	http.Redirect(w, r, "/play", http.StatusTemporaryRedirect)
}

func gameRunner(gameId int32) {
	s2 := rand.NewPCG(uint64(gameId), 1024)
	r2 := rand.New(s2)

	go func() {
		time.Sleep(60 * time.Second)

		gameState := gameStates[gameId]
		if gameState == nil {
			return
		}

		gameState.TimeoutLose()
	}()

	time.Sleep(3 * 1000 * time.Millisecond)

	for {
		time.Sleep(1000 * time.Millisecond)
		gameState := gameStates[gameId]
		if gameState == nil {
			return
		}

		v := r2.IntN(100)

		if v < 20 {
			if gameState.bossHealth < MaxBossHealth*0.8 {
				healAmount := int32(r2.IntN(50) + 20)
				gameState.BossHeal(healAmount)
			} else {
				damageAmount := int32(r2.IntN(30) + 5)
				gameState.BossAttack(damageAmount)
			}
		} else if v < 35 {
			gameState.BossSignalAttack()
			time.Sleep(1000 * time.Millisecond)
			damageAmount := int32(r2.IntN(50) + 10)
			gameState.BossAttack(damageAmount)
		} else if v < 50 {
			damageAmount := int32(r2.IntN(30) + 5)
			gameState.BossAttack(damageAmount)
		} else if v < 65 {
			gameState.BossSignalAttack()
		}
	}
}

func (s *Server) WebsocketHandler(w http.ResponseWriter, r *http.Request) {
	_, claims, _ := jwtauth.FromContext(r.Context())
	gameId := int32(claims["game_id"].(float64))

	gameState := gameStates[gameId]
	if gameState == nil {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]interface{}{"status": "error", "message": "Game not found"})
		return
	}

	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	gameState.conn = conn
	gameState.SyncJSON()
}
