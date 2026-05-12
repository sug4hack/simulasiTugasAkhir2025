// ======= file: keygen_server.go (Port 9080, endpoint /keygen) =======
package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"context"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/argon2"

	_ "github.com/go-sql-driver/mysql"
)

var validLengths = map[int]bool{16: true, 24: true, 32: true}

type EncryptionService struct {
	db           *sql.DB
	store        *sessions.CookieStore
	logger       *logrus.Logger
	argonTime    uint32
	argonMemory  uint32
	argonThreads uint8
}

func NewEncryptionService(db *sql.DB, store *sessions.CookieStore, logger *logrus.Logger) *EncryptionService {
	return &EncryptionService{
		db:           db,
		store:        store,
		logger:       logger,
		argonTime:    3,
		argonMemory:  64 * 1024,
		argonThreads: 4,
	}
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "" || !strings.HasPrefix(auth, "Basic ") {
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}
		payload, _ := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		pair := strings.SplitN(string(payload), ":", 2)

		// Ambil kredensial dari ENV, fallback ke nilai lama agar perilaku tidak berubah
		envUser := os.Getenv("BASIC_AUTH_USER")
		if envUser == "" {
			envUser = "username"
		}
		envPass := os.Getenv("BASIC_AUTH_PASS")
		if envPass == "" {
			envPass = "pass"
		}

		if len(pair) != 2 || pair[0] != envUser || pair[1] != envPass {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSONResponse(w http.ResponseWriter, code int, status, msg string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": msg,
		"data":    data,
	})
}

func (s *EncryptionService) KeyGenHandler(w http.ResponseWriter, r *http.Request) {
	password := make([]byte, 32)
	rand.Read(password)
	salt := make([]byte, 16)
	rand.Read(salt)
	keys := make(map[string]string)
	for _, l := range []int{16, 24, 32} {
		key := argon2.IDKey(password, salt, s.argonTime, s.argonMemory, s.argonThreads, uint32(l))
		keys[fmt.Sprintf("key%d", l)] = base64.StdEncoding.EncodeToString(key)
	}
	writeJSONResponse(w, http.StatusOK, "success", "Kunci berhasil dihasilkan", keys)
}

func main() {
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	mysqlUser := os.Getenv("MYSQL_USER")
	
	mysqlPassword := os.Getenv("MYSQL_PASSWORD")
	
	mysqlHost := os.Getenv("MYSQL_HOST")
	
	mysqlPort := os.Getenv("MYSQL_PORT")
	
	mysqlDB := os.Getenv("MYSQL_DB")
	

	dsn := mysqlUser + ":" + mysqlPassword + "@tcp(" + mysqlHost + ":" + mysqlPort + ")/" + mysqlDB + "?parseTime=true"
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		logger.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		logger.Fatal(err)
	}

	storeKey := os.Getenv("SESSION_KEY")
	if storeKey == "" {
		storeKey = strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	store := sessions.NewCookieStore([]byte(storeKey))
	service := NewEncryptionService(db, store, logger)

	r := mux.NewRouter()
	r.Use(CORSMiddleware)
	r.Handle("/keygen", BasicAuthMiddleware(http.HandlerFunc(service.KeyGenHandler))).Methods("POST", "OPTIONS")

	// Port server dari ENV, fallback ke 9080 agar perilaku tetap sama
	port := os.Getenv("PORT")
	if port == "" {
		port = "9080"
	}

	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + port,
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal(err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
