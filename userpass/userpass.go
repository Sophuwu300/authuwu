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
	Username string   `storm:"id,unique,index"`
	Password Password `storm:"inline"`
}

func (u *User) String() string {
	return u.Username + ":" + u.Password.Encode()
}

func NewUser(username string, password string) error {
	var p Password
	err := p.SetPassword(password)
	if err != nil {
		return err
	}
	u, _ := GetUser(username)
	if u != nil && u.Username == username {
		u.Password = p
		return db.AuthUwu.Update(u)
	}
	u = &User{
		Username: username,
		Password: p,
	}
	return db.AuthUwu.Save(u)
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

func GetUserList() ([]string, error) {
	var users []*User
	err := db.AuthUwu.All(&users)
	if err != nil {
		return nil, err
	}
	var userList []string
	for _, u := range users {
		if u.Username != "" {
			userList = append(userList, u.Username)
		}
	}
	return userList, nil
}

// DeleteUser deletes a user from the database
func DeleteUser(username string) error {
	u := &User{Username: username}
	err := db.AuthUwu.DeleteStruct(u)
	if err != nil {
		return err
	}
	return nil
}
