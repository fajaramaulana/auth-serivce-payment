package config

import (
	"database/sql"
	"fmt"
	"strconv"

	_ "github.com/go-sql-driver/mysql"
)

func ConnectDBMysql(config Config) (*sql.DB, error) {
	// Construct the DSN
	dbUser := config.Get("DB_USER")
	dbPassword := config.Get("DB_PASSWORD")
	dbHost := config.Get("DB_HOST")
	dbPort := config.Get("DB_PORT")
	dbType := config.Get("DB_TYPE")
	dbName := config.Get("DB_NAME")
	port, err := strconv.Atoi(dbPort)
	if err != nil {
		return nil, err
	}
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, port, dbName)
	db, err := sql.Open(dbType, dsn)
	if err != nil {
		return nil, err
	}

	return db, nil
}
