package main

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var secretKey = []byte("your-secret-key")

type Todo struct {
	Text string `json:"text"`
	Done bool   `json:"done"`
}

var todos []Todo

func main() {
	r := gin.Default()

	// Endpoint utama untuk melihat daftar todo
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"todos": todos,
		})
	})

	// Menambahkan todo (Hanya bisa jika login)
	r.POST("/add", authenticateMiddleware, func(c *gin.Context) {
		text := c.PostForm("todo")
		username, _ := c.Get("username") // Ambil username dari token

		if text == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Todo cannot be empty"})
			return
		}

		todo := Todo{Text: text, Done: false}
		todos = append(todos, todo)

		c.JSON(http.StatusOK, gin.H{
			"message":  "Todo added successfully",
			"added_by": username,
			"todos":    todos, // Kirim daftar terbaru
		})
	})

	// Toggle status todo (Done / Not Done)
	r.POST("/toggle", authenticateMiddleware, func(c *gin.Context) {
		indexStr := c.PostForm("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(todos) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid index"})
			return
		}

		todos[index].Done = !todos[index].Done
		username, _ := c.Get("username")

		c.JSON(http.StatusOK, gin.H{
			"message":     "Todo status toggled",
			"todo":        todos[index],
			"modified_by": username,
			"todos":       todos,
		})
	})

	// Login dan mendapatkan token JWT
	r.POST("/login", func(c *gin.Context) {
		username := c.PostForm("username")
		password := c.PostForm("password")

		if username == "" || password == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username or password cannot be empty"})
			return
		}

		if (username == "employee" && password == "password") || (username == "senior" && password == "password") {
			encodedPassword := base64.StdEncoding.EncodeToString([]byte(password))
			tokenString, err := createToken(username, encodedPassword)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
				return
			}

			c.JSON(http.StatusOK, gin.H{
				"message":  "Login successful",
				"token":    tokenString,
				"username": username,
				"password": encodedPassword,
			})
		} else {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		}
	})

	// Logout hanya menghapus token di sisi client (tidak ada session di server)
	r.GET("/logout", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "Logout successful"})
	})

	r.Run(":8080")
}

// Membuat token JWT
func createToken(username, encodedPassword string) (string, error) {
	claims := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": username, // Perbaikan: gunakan username sebagai key utama
		"name":     encodedPassword,
		"exp":      time.Now().Add(time.Hour).Unix(),
		"iat":      time.Now().Unix(),
	})

	tokenString, err := claims.SignedString(secretKey)
	return tokenString, err
}

// Memverifikasi token JWT
func verifyToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return secretKey, nil
	})

	if err != nil || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return token, nil
}

// Middleware untuk mengecek otorisasi pengguna
func authenticateMiddleware(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing Authorization header"})
		c.Abort()
		return
	}

	// Ekstrak token setelah "Bearer "
	var tokenString string
	fmt.Sscanf(authHeader, "Bearer %s", &tokenString)

	// Verifikasi token JWT
	token, err := verifyToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		c.Abort()
		return
	}

	// Ambil klaim dari token
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token claims"})
		c.Abort()
		return
	}

	// Pastikan klaim "username" tersedia
	username, usernameExists := claims["username"].(string)
	if !usernameExists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token structure"})
		c.Abort()
		return
	}

	// Simpan data pengguna di context agar bisa digunakan di endpoint lain
	c.Set("username", username)
	c.Set("password", claims["name"])

	// Lanjut ke handler berikutnya
	c.Next()
}
