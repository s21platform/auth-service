//go:generate mockgen -destination=mock_contract_test.go -package=${GOPACKAGE} -source=contract.go
package service

import "context"

type SchoolS interface {
	DoLogin(ctx context.Context, email, password string) (string, error)
}

type CommunityS interface {
	CheckPeer(ctx context.Context, email string) (bool, error)
}

type RedisR interface {
	Get()
	Set()
}
