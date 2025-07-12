package db

import (
	"github.com/asdine/storm/v3"
)

var AuthUwu *storm.DB

func Open(path string) error {
	db, err := storm.Open(path)
	if err != nil {
		return err
	}
	AuthUwu = db
	return nil
}

func Close() error {
	if AuthUwu == nil {
		return nil
	}
	err := AuthUwu.Close()
	AuthUwu = nil
	return err
}
