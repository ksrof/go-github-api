package main

import (
	"log"

	"github.com/ksrof/go-github-api/authorization"
)

func main() {
	auth, err := authorization.New(
		authorization.WithToken("ghp_a2gcJYu1lxkgVDduggjh6x1plhbJcQxDz9W0"),
	)
	if err != nil {
		log.Fatalf("error: %s", err.Error())
	}

	token := auth.Basic()
	log.Printf("token: %s", token)
}
