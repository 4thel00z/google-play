package google_play

import (
	"io"
	"net/http"
)

/**
*	This module is intended to mimic the requests module in python
**/

func Get(url string, params, headers *map[string]string, proxy *http.Transport, cookies *[]http.Cookie) (resp *http.Response, err error) {
	var client = http.DefaultClient

	if proxy != nil {
		client = &http.Client{Transport: proxy}
	}
	request, err := http.NewRequest("GET", url, nil)

	if err != nil {
		return nil, err
	}

	if params != nil && len(*params) != 0 {
		q := request.URL.Query()
		for k, v := range *params {
			q.Add(k, v)
		}
		request.URL.RawQuery = q.Encode()
	}
	if headers != nil {
		for k, v := range *headers {
			request.Header.Add(k, v)
		}
	}
	if cookies != nil {
		for _, cookie := range *cookies {
			request.AddCookie(&cookie)
		}
	}
	return client.Do(request)

}
func Post(url string, body io.Reader, headers *map[string]string, proxy *http.Transport, cookies *[]http.Cookie) (resp *http.Response, err error) {
	var client = http.DefaultClient
	if proxy != nil {
		client = &http.Client{Transport: proxy}
	}
	request, err := http.NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	if headers != nil {
		for k, v := range *headers {
			request.Header.Add(k, v)
		}
	}

	if cookies != nil {
		for _, cookie := range *cookies {
			request.AddCookie(&cookie)
		}
	}

	return client.Do(request)
}

func PostForm(target string, params, headers map[string]string, proxy *http.Transport, cookies *[]http.Cookie) (resp *http.Response, err error) {
	var client = http.DefaultClient
	if proxy != nil {
		client = &http.Client{Transport: proxy}
	}
	request, err := http.NewRequest("POST", target, nil)
	if err != nil {
		return nil, err
	}
	request.PostForm = map[string][]string{}
	if params != nil && len(params) != 0 {
		for k, v := range params {
			request.PostForm.Set(k, v)
		}
	}

	for k, v := range headers {
		request.Header.Add(k, v)
	}

	if cookies != nil {
		for _, cookie := range *cookies {
			request.AddCookie(&cookie)
		}
	}
	return client.Do(request)
}
