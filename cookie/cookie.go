package cookie

import (
	"crypto/rand"
	"errors"
	"git.sophuwu.com/authuwu/db"
	"git.sophuwu.com/authuwu/standard"
	"github.com/asdine/storm/v3/q"
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

func random(len int) ([]byte, error) {
	b := make([]byte, len)
	n, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	if n != len {
		return nil, errors.New("failed to read enough random bytes")
	}
	return b, nil
}

func NewCookie(user string, expires time.Duration) (http.Cookie, error) {
	b, err := random(standard.CookieLength)
	if err != nil {
		return http.Cookie{}, err
	}
	var c Cookie
	c.Secret = b
	c.User = user
	c.Expires = time.Now().Add(expires)
	err = db.AuthUwu.Save(&c)
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

func PurgeExpiredCookies() error {
	var cookies []Cookie
	err := db.AuthUwu.Select(q.Lte("Expires", time.Now())).Find(&cookies)
	if err != nil {
		return err
	}
	for _, c := range cookies {
		err = db.AuthUwu.DeleteStruct(&c)
		if err != nil {
			return err
		}
	}
	return nil
}

func GetAllCookies() ([]Cookie, error) {
	var cookies []Cookie
	err := db.AuthUwu.All(&cookies)
	if err != nil {
		return nil, err
	}
	return cookies, nil
}
