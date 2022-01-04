package controllers

import (
	"crypto/rand"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"time"

	model "app/models"
	u "app/utils"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	_ "github.com/lib/pq"
	"gopkg.in/olahol/melody.v1"
)

var jwtKey = []byte("diamond")

func SignUp(ctx *gin.Context) {

	var newUser model.User

	err := ctx.BindJSON(&newUser)

	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("postgres", u.PGConnection)

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	var check int

	err = db.QueryRow(
		model.SQL_JOINER,
		newUser.Gmail,
	).Scan(
		&check,
	)

	if err != nil {

		parol, _ := rand.Prime(rand.Reader, 32)

		parolString := parol.String()

		db.Exec(
			model.SQL_INSERT,
			newUser.Username,
			newUser.Gmail,
			parolString,
		)

		ctx.IndentedJSON(http.StatusCreated, fmt.Sprintf("User Created Password %s ", parolString))

	} else {

		ctx.IndentedJSON(http.StatusForbidden, "User Existing")
	}

}

func Login(ctx *gin.Context) {

	var output model.Static
	var user model.UserLogin

	err := ctx.BindJSON(&user)

	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("postgres", u.PGConnection)

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	var check int

	err = db.QueryRow(
		model.SQL_LOGIN,
		user.Login,
		user.Password,
	).Scan(&check)

	if err != nil {

		time := time.Now().Add(2 * time.Hour)

		jwtParol := model.Token{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtParol)

		tokenString, err := token.SignedString(jwtKey)

		if err != nil {
			log.Fatal(err)
		}

		err = db.QueryRow(
			model.SQL_ADD_TOKEN,
			user.Login,
			user.Password,
			tokenString,
		).Scan(
			&output.Token,
			&output.User.Username,
			&output.User.Gmail,
		)

		if err == nil {

			ctx.IndentedJSON(http.StatusOK, output)

		} else {

			ctx.IndentedJSON(http.StatusForbidden, "User Existing")

		}

	} else {

		err = db.QueryRow(
			model.SQL_SELECT_USER,
			check,
		).Scan(
			&output.Token,
			&output.User.Username,
			&output.User.Gmail,
		)

		if err != nil {
			log.Fatal(err)
		}

		ctx.IndentedJSON(http.StatusOK, output)

	}
}

func ChangePassword(ctx *gin.Context) {

	var output model.Static
	var newPassword model.ChangePass

	err := ctx.BindJSON(&newPassword)

	if err != nil {
		log.Fatal(err)
	}

	db, err := sql.Open("postgres", u.PGConnection)

	if err != nil {
		log.Fatal(err)
	}

	defer db.Close()

	var check int

	err = db.QueryRow(
		model.SQL_CHANGE_PASS,
		newPassword.Login,
		newPassword.OldPassword,
		newPassword.NewPassword,
	).Scan(&check)

	if err == nil {

		time := time.Now().Add(2 * time.Hour)

		jwtParol := model.Token{
			StandardClaims: jwt.StandardClaims{
				ExpiresAt: time.Unix(),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwtParol)

		tokenString, err := token.SignedString(jwtKey)

		if err != nil {
			log.Fatal(err)
		}

		err = db.QueryRow(
			model.SQL_CHANGE_TOKEN,
			newPassword.Login,
			newPassword.NewPassword,
			tokenString,
		).Scan(
			&output.Token,
			&output.User.Username,
			&output.User.Gmail,
		)

		if err != nil {
			log.Fatal(err)
		}

		ctx.IndentedJSON(http.StatusOK, output)

	} else {

		ctx.IndentedJSON(403, "Failed Change Password")
	}
}

func WebSocket(ctx *gin.Context) {

	websocketRouter := melody.New()

	tok := ctx.GetHeader("accesToken")

	token := &model.Token{}

	tkn, err := jwt.ParseWithClaims(tok, token, func(tok *jwt.Token) (interface{}, error) {

		return jwtKey, nil

	})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			ctx.AbortWithStatus(401)
			return
		}
		ctx.AbortWithStatus(401)

		return
	}

	if !tkn.Valid {

		ctx.AbortWithStatus(401)
		return
	}

	ctx.AbortWithStatus(200)

	websocketRouter.HandleMessage(func(s *melody.Session, m []byte) {

		websocketRouter.Broadcast(m)

	})

}
