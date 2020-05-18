package main

import (
	"fmt"
	google_play "github.com/4thel00z/google-play"
	"os"
)

func main() {

	password := os.Getenv("GP_PASSWORD")
	username := os.Getenv("GP_USERNAME")

	api, err := google_play.Api("/home/ransomware/go/src/github.com/4thel00z/google-play/devices.json", "alien_jolla_bionic", "", "", nil)
	if err != nil {
		panic(err)
	}

	_, err = api.FetchAASToken(username, password)
	if err != nil {
		panic(err)
	}
	err = api.LoginWithEmailAndPassword(username, password)
	if err != nil {
		panic(err)
	}
	fmt.Printf("GSFID [%d]\n", api.GsfId)
	fmt.Printf("TOKEN [%s]\n", api.AuthSubToken)
	search, err := api.Search("quran")
	if err != nil {
		panic(err)
	}
	fmt.Println(search)
}
