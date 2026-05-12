package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	"context"

	"github.com/gorilla/mux"      // Router HTTP
	"github.com/gorilla/sessions" // Penyimpanan sesi menggunakan cookie
	"github.com/sirupsen/logrus"  // Logging dengan format JSON

	_ "github.com/go-sql-driver/mysql" // Driver MySQL
)

type EncryptionService struct {
	db           *sql.DB               // Koneksi ke database
	store        *sessions.CookieStore // Penyimpanan sesi berbasis cookie
	logger       *logrus.Logger        // Logger untuk pencatatan
	argonTime    uint32                // Parameter waktu untuk Argon2
	argonMemory  uint32                // Parameter memori untuk Argon2
	argonThreads uint8                 // Parameter thread untuk Argon2
}

var validLengths = map[int]bool{
	16: true,
	24: true,
	32: true,
}

// Fungsi untuk membuat layanan enkripsi
func NewEncryptionService(db *sql.DB, store *sessions.CookieStore, logger *logrus.Logger) *EncryptionService {
	return &EncryptionService{
		db:           db,
		store:        store,
		logger:       logger,
		argonTime:    3,         // Set default Argon2 time parameter
		argonMemory:  64 * 1024, // Set default Argon2 memory parameter (64 MB)
		argonThreads: 4,         // Set default Argon2 threads parameter
	}
}

// Middleware untuk mengatur CORS
func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Menambahkan header CORS
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")

		// Menghentikan proses jika metode adalah OPTIONS (preflight request)
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Middleware untuk otentikasi berbasis Basic Auth
func BasicAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Meminta otentikasi jika header Authorization kosong
		auth := r.Header.Get("Authorization")
		if auth == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="Please enter your username and password"`)
			http.Error(w, "Authorization required", http.StatusUnauthorized)
			return
		}

		if !strings.HasPrefix(auth, "Basic ") {
			http.Error(w, "Invalid Authorization header", http.StatusBadRequest)
			return
		}

		// Mendekodekan nilai Authorization untuk mendapatkan username dan password
		payload, err := base64.StdEncoding.DecodeString(auth[len("Basic "):])
		if err != nil {
			http.Error(w, "Authorization header could not be decoded", http.StatusBadRequest)
			return
		}

		// Memvalidasi username dan password
		pair := strings.SplitN(string(payload), ":", 2)
		if len(pair) != 2 || !validateCredentials(pair[0], pair[1]) {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Fungsi untuk memvalidasi username dan password
func validateCredentials(username, password string) bool {
	// Baca dari ENV, fallback ke nilai lama agar perilaku default TETAP sama
	envUser := os.Getenv("BASIC_AUTH_USER")
	if envUser == "" {
		envUser = "BASIC_AUTH_USER"
	}
	envPass := os.Getenv("BASIC_AUTH_PASS")
	if envPass == "" {
		envPass = "BASIC_AUTH_PASS"
	}
	return username == envUser && password == envPass
}

// Fungsi untuk menulis respons JSON
func writeJSONResponse(w http.ResponseWriter, statusCode int, status string, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":  status,
		"message": message,
		"data":    data,
	})
}

// Fungsi untuk menghasilkan password acak
func GenerateRandomPassword(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func encryption(plaintext []byte, key []byte, aad []byte) ([]byte, error) {
	// Validasi panjang kunci !validLengths[num]
	if !validLengths[len(key)] {
		return nil, fmt.Errorf("invalid key length, got %d bytes", len(key))
	}

	// Buat AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Buat mode GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Buat nonce acak
	nonce := make([]byte, aesgcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Enkripsi plaintext
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, aad)

	// Kombinasikan nonce dan ciphertext
	return append(nonce, ciphertext...), nil
}

func decryption(encryptedData []byte, key []byte, aad []byte) ([]byte, error) {
	// Validasi panjang kunci
	if !validLengths[len(key)] {
		return nil, fmt.Errorf("invalid key length, got %d bytes", len(key))
	}

	// Buat AES cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	// Buat mode GCM
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Pastikan encryptedData memiliki panjang minimal untuk nonce + tag
	nonceSize := aesgcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, fmt.Errorf("invalid encrypted data: too short to contain nonce")
	}

	// Pisahkan nonce dan ciphertext
	nonce := encryptedData[:nonceSize]
	ciphertext := encryptedData[nonceSize:]

	// Dekripsi ciphertext
	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (s *EncryptionService) EncryptHandler(w http.ResponseWriter, r *http.Request) {
	s.handleCryptoRequest(w, r, true)
}

func (s *EncryptionService) DecryptHandler(w http.ResponseWriter, r *http.Request) {
	s.handleCryptoRequest(w, r, false)
}

func (s *EncryptionService) processKey(r *http.Request) ([]byte, error) {
	keyBase64 := r.FormValue("key")
	key, err := base64.StdEncoding.DecodeString(keyBase64)
	if err != nil {
		return nil, fmt.Errorf("format kunci tidak valid: %v", err)
	}

	if !validLengths[len(key)] {
		return nil, fmt.Errorf("panjang kunci tidak valid: %d byte", len(key))
	}

	return key, nil
}

func (s *EncryptionService) handleCryptoRequest(w http.ResponseWriter, r *http.Request, isEncrypt bool) {
	// Baca file
	data, filename, err := s.readUploadedFile(r)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "File processing failed", err)
		return
	}

	key, err := s.processKey(r)
	if err != nil {
		s.writeErrorResponse(w, http.StatusBadRequest, "Gagal memproses kunci", err)
		return
	}

	aad := []byte(r.FormValue("aad"))

	// Enkripsi/Deskripsi
	var result []byte
	if isEncrypt {
		result, err = encryption(data, key, aad)
	} else {
		result, err = decryption(data, key, aad)
	}
	if err != nil {
		s.writeErrorResponse(w, http.StatusInternalServerError, "Crypto operation failed", err)
		return
	}
	// Set headers dan kirim response
	s.sendFileResponse(w, filename, isEncrypt, result)
}

// Helper functions
func (s *EncryptionService) readUploadedFile(r *http.Request) ([]byte, string, error) {
	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32MB max memory
		return nil, "", fmt.Errorf("failed to parse multipart form: %v", err)
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, "", fmt.Errorf("file upload failed: %v", err)
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, 100<<20)) // 100MB max
	if err != nil {
		return nil, "", fmt.Errorf("file read failed: %v", err)
	}

	return data, sanitizeFilename(header.Filename), nil
}

func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	name = strings.TrimPrefix(name, filepath.Ext(name))
	return strings.Map(func(r rune) rune {
		if unicode.IsPrint(r) && !strings.ContainsRune("/\\?%*:|\"<>", r) {
			return r
		}
		return '_'
	}, name)
}

func (s *EncryptionService) sendFileResponse(w http.ResponseWriter, filename string, isEncrypt bool, data []byte) {
	ext := ".enc"
	if !isEncrypt {
		ext = strings.TrimSuffix(filepath.Ext(filename), ".enc")
		filename = filename[:len(filename)-len(ext)]
	} else {
		filename += ext
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	_, _ = w.Write(data)
}

func (s *EncryptionService) writeErrorResponse(w http.ResponseWriter, status int, message string, err error) {
	// tetap pakai logger yang ada
	s.logger.Printf("%s: %v", message, err)
	writeJSONResponse(w, status, "error", message, map[string]interface{}{
		"details": err.Error(),
	})
}

type KeyParams struct {
	Password string
	Salt     []byte
	Length   int
}

func main() {
	// Membuat logger untuk pencatatan log
	logger := logrus.New()
	logger.SetFormatter(&logrus.JSONFormatter{})

	// Membaca variabel lingkungan untuk koneksi MySQL
	mysqlUser := os.Getenv("MYSQL_USER")
	mysqlPassword := os.Getenv("MYSQL_PASSWORD")
	mysqlHost := os.Getenv("MYSQL_HOST")
	mysqlPort := os.Getenv("MYSQL_PORT")
	mysqlDB := os.Getenv("MYSQL_DB")

	// Membuat string koneksi MySQL
	dsn := mysqlUser + ":" + mysqlPassword + "@tcp(" + mysqlHost + ":" + mysqlPort + ")/" + mysqlDB + "?parseTime=true"

	// Membuka koneksi ke database
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		logger.Fatal("Failed to connect to MySQL: ", err)
	}
	defer db.Close()

	// Memeriksa koneksi ke database
	err = db.Ping()
	if err != nil {
		logger.Fatal("Failed to ping MySQL: ", err)
	}

	// Membuat penyimpanan sesi menggunakan cookie
	storeKey := os.Getenv("SESSION_KEY")
	if storeKey == "" {
		storeKey, err = GenerateRandomPassword(64)
		if err != nil {
			log.Fatal(err)
		}
	}

	store := sessions.NewCookieStore([]byte(storeKey))

	// Membuat layanan enkripsi
	service := NewEncryptionService(db, store, logger)

	// Membuat router HTTP dan menambahkan middleware
	r := mux.NewRouter()
	r.Use(CORSMiddleware)

	// Menambahkan rute untuk API
	r.Handle("/encrypt", BasicAuthMiddleware(http.HandlerFunc(service.EncryptHandler))).Methods(http.MethodPost, http.MethodOptions)
	r.Handle("/decrypt", BasicAuthMiddleware(http.HandlerFunc(service.DecryptHandler))).Methods(http.MethodPost, http.MethodOptions)

	// Port server dari ENV, fallback ke 8090 agar perilaku lama tetap sama
	port := os.Getenv("PORT")
	if port == "" {
		port = "8090"
	}

	// Menjalankan server HTTP
	srv := &http.Server{
		Handler:      r,
		Addr:         ":" + port,
		WriteTimeout: 60 * time.Second,
		ReadTimeout:  60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Menangani sinyal penghentian server
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed: ", err)
		}
	}()

	// Menunggu sinyal penghentian
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	// Menutup server dengan aman
	logger.Info("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		logger.Fatal("Server forced to shutdown: ", err)
	}

	logger.Info("Server exiting")
}
