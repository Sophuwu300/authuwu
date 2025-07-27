package db

import (
	"github.com/asdine/storm/v3"
	"go.etcd.io/bbolt"
	"time"
)

var AuthUwu *storm.DB

func Open(path string) error {
	db, err := storm.Open(path, storm.BoltOptions(0660, &bbolt.Options{
		Timeout: time.Second,
	}))
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
