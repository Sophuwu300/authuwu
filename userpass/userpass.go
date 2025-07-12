package userpass

import (
	"crypto/rand"
	"crypto/subtle"
	"git.sophuwu.com/authuwu/db"
	"git.sophuwu.com/authuwu/standard"
)

type Password struct {
	Hash []byte
	Salt []byte
}

func (p *Password) Encode() string {
	e := standard.NewEncoder()
	s := e.EncodeToString(p.Hash)
	s += ":"
	s += e.EncodeToString(p.Salt)
	return s
}

func (p *Password) CheckPassword(password string) bool {
	h := standard.NewHash()
	h.Write(p.Salt)
	h.Write([]byte(password))
	b := h.Sum(nil)
	return 1 == subtle.ConstantTimeCompare(b, p.Hash)
}

func Salt() ([]byte, error) {
	salt := make([]byte, standard.SaltLength)
	_, err := rand.Read(salt)
	return salt, err
}

func (p *Password) SetPassword(password string) error {
	salt, err := Salt()
	if err != nil {
		return err
	}
	p.Salt = salt
	h := standard.NewHash()
	h.Write(salt)
	h.Write([]byte(password))
	p.Hash = h.Sum(nil)
	return nil
}

func (u *User) SetPassword(password string) error {
	if err := u.Password.SetPassword(password); err != nil {
		return err
	}
	return nil
}

func (u *User) Authenticate(password string) bool {
	return u.Password.CheckPassword(password)
}

type User struct {
	Username string   `storm:"id"`
	Password Password `storm:"inline"`
}

func (u *User) String() string {
	return u.Username + ":" + u.Password.Encode()
}

func NewUser(username string, password string) error {
	u := &User{Username: username}
	err := u.SetPassword(password)
	if err != nil {
		return err
	}
	err = db.AuthUwu.Save(u)
	return err
}

func GetUser(username string) (*User, error) {
	u := &User{Username: username}
	err := db.AuthUwu.One("Username", username, u)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func UserAuth(username string, password string) (bool, error) {
	u, err := GetUser(username)
	if err != nil {
		return false, err
	}
	return u.Authenticate(password), nil
}
