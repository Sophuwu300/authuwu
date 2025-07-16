package authuwu

import (
	"fmt"
	"git.sophuwu.com/authuwu/cookie"
	uwudb "git.sophuwu.com/authuwu/db"
	"git.sophuwu.com/authuwu/userpass"
	"net/http"
	"time"
)

func OpenDB(path string) error {
	return uwudb.Open(path)
}
func CloseDB() error {
	return uwudb.Close()
}

func NewAuthuwuHandler(h http.Handler, cookieTime time.Duration, loginPage string) *AuthuwuHandler {
	if loginPage == "" {
		loginPage = LoginPage
	}
	return &AuthuwuHandler{
		Handler:    h,
		CookieTime: cookieTime,
		LoginPage:  loginPage,
	}
}

type AuthuwuHandler struct {
	Handler    http.Handler
	CookieTime time.Duration
	LoginPage  string
}

// LoginPage is the HTML template for the login page. Should contain a form that submits to the login handler.
// Must action to "?authuwu:login" with method POST.
// Must contain inputs for username, password
var LoginPage = `<html>
<head>
<title>Login</title>
</head>
<body>
<h1>Login</h1>
<form method="POST" action="?authuwu:login">
<label for="username">Username:</label>
<input type="text" id="username" name="username" required>
<label for="password">Password:</label>
<input type="password" id="password" name="password" required>
<input type="submit" value="Login">
</form>
</body>
</html>
`

func (h *AuthuwuHandler) loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, h.LoginPage)
		w.WriteHeader(http.StatusOK)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Redirect(w, r, r.URL.Path+"?authuwu:login", http.StatusBadRequest)
		return
	}
	ok, err := userpass.UserAuth(username, password)
	if err != nil || !ok {
		http.Redirect(w, r, r.URL.Path+"?authuwu:login", http.StatusUnauthorized)
		return
	}
	c, err := cookie.NewCookie(username, h.CookieTime)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &c)
	http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
}

func (h *AuthuwuHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery == "authuwu:login" {
		h.loginHandler(w, r)
		return
	}
	ok, user, err := cookie.GetCookie(r)
	if err == nil && ok && user != "" {
		var u *userpass.User
		u, err = userpass.GetUser(user)
		if err == nil && u != nil && u.Username != "" {
			if r.URL.RawQuery == "authuwu:logout" {
				_ = cookie.DeleteCookie(r)
				http.Redirect(w, r, r.URL.Path, http.StatusSeeOther)
				return
			}
			h.Handler.ServeHTTP(w, r)
			return
		}
	}
	h.loginHandler(w, r)
}
