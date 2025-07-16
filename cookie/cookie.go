package cookie

import (
	"git.sophuwu.com/authuwu/db"
	"git.sophuwu.com/authuwu/standard"
	"net/http"
	"time"
)

type Cookie struct {
	Secret  []byte    `storm:"id,unique,index"`
	User    string    `storm:"index"`
	Expires time.Time `storm:"index"`
}

func (c *Cookie) Encode() string {
	return standard.NewEncoder().EncodeToString(c.Secret)
}

func random(len int) []byte {
	b := make([]byte, len)
	return b
}

func NewCookie(user string, expires time.Duration) (http.Cookie, error) {
	b := random(standard.CookieLength)
	var c Cookie
	c.Secret = b
	c.User = user
	c.Expires = time.Now().Add(expires)
	err := db.AuthUwu.Save(&c)
	if err != nil {
		return http.Cookie{}, err
	}
	return http.Cookie{
		Name:     "authuwu_session",
		Value:    c.Encode(),
		Expires:  c.Expires,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
	}, err
}

func CheckCookie(secret string) (bool, string, error) {
	var c Cookie
	b, err := standard.NewEncoder().DecodeString(secret)
	if err != nil || len(b) != standard.CookieLength {
		return false, "", err
	}
	err = db.AuthUwu.One("Secret", b, &c)
	if err != nil {
		return false, "", err
	}
	if time.Now().After(c.Expires) {
		err = db.AuthUwu.DeleteStruct(&c)
		return false, "", err
	}
	return true, c.User, nil
}

func GetCookie(r *http.Request) (bool, string, error) {
	c, err := r.Cookie("authuwu_session")
	if err != nil || c == nil {
		return false, "", err
	}
	return CheckCookie(c.Value)
}

func DeleteCookie(r *http.Request) error {
	c, err := r.Cookie("authuwu_session")
	if err != nil || c == nil {
		return err
	}
	b, err := standard.NewEncoder().DecodeString(c.Value)
	if err != nil || len(b) != standard.CookieLength {
		return err
	}
	var cookie Cookie
	cookie.Secret = b
	return db.AuthUwu.DeleteStruct(&cookie)
}
