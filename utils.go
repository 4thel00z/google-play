package google_play

import (
	"io/ioutil"
	"os"
	"strconv"
)

func parsei32(val string) (*int32, error) {
	result64, err := strconv.ParseInt(val, 10, 32)
	if err != nil {
		return nil, err
	}
	result := int32(result64)

	return &result, err
}


func readAll(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return ioutil.ReadAll(f)
}
