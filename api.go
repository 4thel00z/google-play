package google_play

import (
	"errors"
	"fmt"
	"github.com/4thel00z/google-play/pkg"
	"google.golang.org/protobuf/proto"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	Base       = "https://android.clients.google.com/"
	Fdfe       = Base + "fdfe/"
	CheckinUrl = Base + "checkin"
	AuthUrl    = Base + "auth"

	UploadUrl        = Fdfe + "uploadDeviceConfig"
	SearchUrl        = Fdfe + "search"
	DetailsUrl       = Fdfe + "details"
	HomeUrl          = Fdfe + "homeV2"
	BrowseUrl        = Fdfe + "browse"
	DeliveryUrl      = Fdfe + "delivery"
	PurchaseUrl      = Fdfe + "purchase"
	SearchSuggestUrl = Fdfe + "searchSuggest"
	BulkUrl          = Fdfe + "bulkDetails"
	LogUrl           = Fdfe + "log"
	TocUrl           = Fdfe + "toc"
	AcceptTosUrl     = Fdfe + "acceptTos"
	ListUrl          = Fdfe + "list"
	ReviewsUrl       = Fdfe + "rev"

	ContentTypeUrlEncoding = "application/x-www-form-urlencoded; charset=UTF-8"
	ContentTypeProto       = "application/x-protobuf"
	OauthService           = "oauth2:https://www.googleapis.com/auth/googleplay"
)

type LoginError string

func (err LoginError) Error() string {
	return string(err)
}

type RequestError string

func (err RequestError) Error() string {
	return string(err)
}

type SecurityCheckError string

func (err SecurityCheckError) Error() string {
	return string(err)
}

type GooglePlayApi struct {
	AuthSubToken                  string
	GsfId                         uint64
	DeviceConfigToken             string
	Device                        Device
	DeviceCheckinConsistencyToken string
	DfeCookie                     string
	Locale                        string
	Timezone                      string
	Proxy                         *http.Transport
}

func Api(devicesPath string, device string, locale string, timezone string, proxy *http.Transport) (*GooglePlayApi, error) {
	devices, err := ParseDevices(devicesPath)
	if locale == "" {
		locale = "de_DE"
	}
	if timezone == "" {
		timezone = "UTC"
	}
	if err != nil {
		return nil, err
	}
	d, ok := devices[device]

	if !ok {
		return nil, err
	}
	err = d.setLocale(locale)
	if err != nil {
		return nil, err
	}

	err = d.setTimezone(timezone)
	if err != nil {
		return nil, err
	}

	api := GooglePlayApi{
		Device: d,
		Proxy:  proxy,
	}

	return &api, nil
}

func (api *GooglePlayApi) getHeaders(uploadFields bool) map[string]string {
	var headers map[string]string

	if uploadFields {
		headers = api.Device.getUploadHeaders()
	} else {
		headers = api.Device.getBaseHeaders()
	}

	if api.GsfId != 0 {
		headers["X-DFE-Device-Id"] = fmt.Sprintf("%x", api.GsfId)
	}

	// Apparently the switched to using Bearer <token> scheme
	// https://github.com/NoMore201/googleplay-api/pull/114/commits/5a5ab2210571bb90a1769117472db4ade8915b0e
	if api.AuthSubToken != "" {
		headers["Authorization"] = fmt.Sprintf("Bearer %s", api.AuthSubToken)
	}

	if api.DeviceConfigToken != "" {
		headers["X-DFE-Device-Config-Token"] = api.DeviceConfigToken
	}

	if api.DeviceCheckinConsistencyToken != "" {
		headers["X-DFE-Device-Checkin-Consistency-Token"] = api.DeviceCheckinConsistencyToken
	}

	if api.DfeCookie != "" {
		headers["X-DFE-Cookie"] = api.DfeCookie
	}

	return headers
}

func (api *GooglePlayApi) Checkin(email, ac2dmToken string) (*uint64, error) {

	headers := api.getHeaders(false)
	headers["Content-Type"] = ContentTypeProto
	request, err := api.Device.GetAndroidCheckinRequest()
	if err != nil {
		return nil, err
	}
	response, err := Post(CheckinUrl, strings.NewReader(request.String()), &headers, api.Proxy, nil)
	if err != nil {
		return nil, err
	}
	var checkinResponse pkg.AndroidCheckinResponse
	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	err = proto.Unmarshal(raw, &checkinResponse)
	if err != nil {
		return nil, err
	}
	api.DeviceCheckinConsistencyToken = *checkinResponse.DeviceCheckinConsistencyToken

	// checkin again to upload gfsid
	newId := int64(*checkinResponse.AndroidId)
	request.Id = &newId
	request.SecurityToken = checkinResponse.SecurityToken
	request.AccountCookie = append(request.AccountCookie, "["+email+"]", ac2dmToken)
	response, err = Post(CheckinUrl, strings.NewReader(request.String()), &headers, api.Proxy, nil)

	if err != nil {
		return nil, err
	}

	return checkinResponse.AndroidId, err
}

func (api *GooglePlayApi) UploadDeviceConfig(email, ac2dmToken string) error {

	uploadRequest := pkg.UploadDeviceConfigRequest{}

	config, err := api.Device.GetDeviceConfig()
	if err != nil {
		return err
	}
	uploadRequest.DeviceConfiguration = config
	headers := api.getHeaders(true)

	response, err := Post(UploadUrl, strings.NewReader(uploadRequest.String()), &headers, api.Proxy, nil)
	if err != nil {
		return err
	}

	var uploadResponse pkg.UploadDeviceConfigResponse

	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}

	err = proto.Unmarshal(raw, &uploadResponse)
	if err != nil {
		return err
	}
	if uploadResponse.UploadDeviceConfigToken == nil {
		return errors.New("UploadDeviceConfigToken in uploadResponse was not set")
	}

	api.DeviceConfigToken = *uploadResponse.UploadDeviceConfigToken
	return nil

}

func (api *GooglePlayApi) loginWithEmailAndPassword(email, password string) error {

	var (
		ac2dmToken string
	)
	encryptedPass := encrypt(email, password)
	params := api.Device.getLoginParams(email, encryptedPass)
	params["service"] = "ac2dm"
	params["add_account"] = "1"
	params["callerPkg"] = "com.google.android.gms"
	headers := api.Device.getAuthHeader(int(api.GsfId))
	headers["app"] = "com.google.android.gsm"
	response, err := PostForm(AuthUrl, params, headers, api.Proxy, nil)
	if err != nil {
		return err
	}
	structuredData, err := api.parseResponse(response)
	if err != nil {
		return err
	}

	if value, ok := structuredData["auth"]; ok {
		ac2dmToken = value
	} else if value, ok := structuredData["error"]; ok {
		if strings.Contains(value, "NeedsBrowser") {
			return SecurityCheckError("Security check is needed, try to visit " +
				"https://accounts.google.com/b/0/DisplayUnlockCaptcha " +
				"to unlock, or setup an app-specific password")
		}
		return LoginError(fmt.Sprintf("server says: %s", value))
	} else {
		return LoginError("auth token not found")
	}
	gsfId, err := api.Checkin(email, ac2dmToken)
	if err != nil {
		return err
	}

	api.GsfId = *gsfId
	err = api.GetAuthSubToken(email, encryptedPass)

	if err != nil {
		return err
	}
	err = api.UploadDeviceConfig(email, ac2dmToken)
	if err != nil {
		return err
	}

	return nil
}

func (api *GooglePlayApi) loginWithGsfIdAndAuthSubToken(gsfId, authSubToken string) error {
	gsfIdInt, err := strconv.Atoi(gsfId)
	if err != nil {
		return err
	}
	api.GsfId = uint64(gsfIdInt)
	api.AuthSubToken = authSubToken
	_, err = api.Search("drv")
	if err != nil {
		return fmt.Errorf("error while performing simple search for login validation: %e", err)
	}

	return nil
}

func (api *GooglePlayApi) GetAuthSubToken(email string, pass string) error {

	params := api.Device.getLoginParams(email, pass)
	params["service"] = "androidmarket"
	params["app"] = "com.android.vending"
	headers := api.Device.getAuthHeader(int(api.GsfId))
	headers["app"] = "com.android.vending"
	response, err := PostForm(AuthUrl, params, headers, api.Proxy, nil)
	if err != nil {
		return err
	}
	structuredData, err := api.parseResponse(response)
	if err != nil {
		return err
	}

	if value, ok := structuredData["token"]; ok {
		token := value
		secondRoundToken, err := api.GetSecondRoundToken(token, params)
		if err != nil {
			return err
		}
		api.AuthSubToken = secondRoundToken
	} else if value, ok := structuredData["error"]; ok {
		return LoginError(fmt.Sprintf("server says: %s", value))
	} else {
		return LoginError("sub auth token not found")
	}

	return nil
}

func (api *GooglePlayApi) parseResponse(response *http.Response) (map[string]string, error) {
	content, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	data := strings.Fields(string(content))

	structuredData := map[string]string{}
	for _, d := range data {
		if !strings.Contains(d, "=") {
			continue
		}
		splitN := strings.SplitN(d, "=", 1)
		k, v := splitN[0], splitN[1]
		index := strings.ToLower(strings.TrimSpace(k))
		structuredData[index] = strings.TrimSpace(v)
	}
	return structuredData, nil
}

func (api *GooglePlayApi) CallGetApiV2(path string, contentType *string, params *map[string]string) (*pkg.ResponseWrapper, error) {
	if api.AuthSubToken == "" {
		return nil, LoginError("you need to login first")
	}

	if contentType == nil {
		s := ContentTypeProto
		contentType = &s
	}

	headers := api.getHeaders(false)
	headers["Content-Type"] = *contentType
	response, err := Get(path, params, &headers, api.Proxy, nil)
	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var wrapper pkg.ResponseWrapper

	err = proto.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}
	if wrapper.Commands != nil && wrapper.Commands.DisplayErrorMessage != nil {
		return nil, RequestError(*wrapper.Commands.DisplayErrorMessage)
	}

	return &wrapper, nil
}

func (api *GooglePlayApi) CallPostApiV2(path string, contentType *string, body io.Reader) (*pkg.ResponseWrapper, error) {
	if api.AuthSubToken == "" {
		return nil, LoginError("you need to login first")
	}

	if contentType == nil {
		s := ContentTypeProto
		contentType = &s
	}
	headers := api.getHeaders(false)
	headers["Content-Type"] = *contentType
	response, err := Post(path, body, &headers, api.Proxy, nil)
	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var wrapper pkg.ResponseWrapper

	err = proto.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}
	if wrapper.Commands != nil && wrapper.Commands.DisplayErrorMessage != nil {
		return nil, RequestError(*wrapper.Commands.DisplayErrorMessage)
	}

	return &wrapper, nil

}

func (api *GooglePlayApi) CallPostFormApiV2(path string, form map[string]string) (*pkg.ResponseWrapper, error) {
	if api.AuthSubToken == "" {
		return nil, LoginError("you need to login first")
	}

	headers := api.getHeaders(false)
	response, err := PostForm(path, form, headers, api.Proxy, nil)
	if err != nil {
		return nil, err
	}

	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var wrapper pkg.ResponseWrapper

	err = proto.Unmarshal(raw, &wrapper)
	if err != nil {
		return nil, err
	}
	if wrapper.Commands != nil && wrapper.Commands.DisplayErrorMessage != nil {
		return nil, RequestError(*wrapper.Commands.DisplayErrorMessage)
	}

	return &wrapper, nil

}
func (api *GooglePlayApi) GetSecondRoundToken(token string, params map[string]string) (string, error) {

	if api.GsfId != 0 {
		params["androidId"] = fmt.Sprintf("%x", api.GsfId)
	}
	params["Token"] = token
	params["check_email"] = "1"
	params["token_request_options"] = "CAA4AQ=="
	params["system_partition"] = "1"
	params["_opt_is_called_from_account_manager"] = "1"
	delete(params, "Email")
	delete(params, "EncryptedPasswd")
	headers := api.Device.getAuthHeader(int(api.GsfId))
	headers["app"] = "com.android.vending"
	response, err := PostForm(AuthUrl, params, headers, api.Proxy, nil)
	if err != nil {
		return "", err
	}

	structuredData, err := api.parseResponse(response)
	if err != nil {
		return "", err
	}
	if value, ok := structuredData["auth"]; ok {
		return value, nil
	} else if value, ok := structuredData["error"]; ok {
		return "", LoginError(fmt.Sprintf("server says: %s", value))
	} else {
		return "", LoginError("second round auth token not found")
	}
}

func (api *GooglePlayApi) SearchSuggest(query string) ([]*pkg.SearchSuggestEntry, error) {
	params := map[string]string{
		"c": "3",
		//check if this corresponds to requests.utils.quote(query)
		"q":    url.QueryEscape(query),
		"ssis": "120",
		"sst":  "2",
	}
	response, err := api.CallGetApiV2(SearchSuggestUrl, nil, &params)
	if err != nil {
		return nil, err
	}
	if response.Payload == nil ||
		response.Payload.SearchSuggestResponse == nil ||
		response.Payload.SearchSuggestResponse.Entry == nil {
		return nil, RequestError("there was an error with the SearchSuggest call")
	}

	// maybe unpack
	return response.Payload.SearchSuggestResponse.Entry, nil
}

func (api *GooglePlayApi) toc() error {
	if api.AuthSubToken == "" {
		return LoginError("you need to login first")
	}

	headers := api.getHeaders(false)
	headers["Content-Type"] = ContentTypeUrlEncoding
	response, err := Get(TocUrl, nil, &headers, api.Proxy, nil)
	if err != nil {
		return err
	}

	raw, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return err
	}
	var wrapper pkg.TocResponse

	err = proto.Unmarshal(raw, &wrapper)
	if err != nil {
		return err
	}
	if wrapper.TosToken != nil {
		err = api.acceptTosToken(*wrapper.TosToken)
		if err != nil {
			return err
		}
	}
	if wrapper.Cookie != nil {
		api.DfeCookie = *wrapper.Cookie
	}

	return nil
}

func (api *GooglePlayApi) Search(query string) ([]*pkg.DocV2, error) {
	path := SearchUrl + fmt.Sprintf("?c=3&q=%s", url.QueryEscape(query))
	err := api.toc()
	if err != nil {
		return nil, err
	}

	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}

	if response.PreFetch != nil {
		return response.PreFetch[0].Response.Payload.ListResponse.Doc, nil
	} else {
		return response.Payload.ListResponse.Doc, nil
	}

}

func (api *GooglePlayApi) acceptTosToken(token string) error {
	params := map[string]string{
		"tost":   token,
		"toscme": "false",
	}
	_, err := api.CallGetApiV2(AcceptTosUrl, nil, &params)
	if err != nil {
		return err
	}
	return nil

}

/**
Get app details from a package name.
@packageName is the app unique ID (usually starting with 'com.' or other TLDs).
*/
func (api *GooglePlayApi) Details(packageName string) (*pkg.DocV2, error) {
	path := DetailsUrl + fmt.Sprintf("?doc=%s", url.QueryEscape(packageName))
	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}
	return response.Payload.DetailsResponse.DocV2, nil
}

func (api *GooglePlayApi) BulkDetails(packageNames []string) ([]pkg.DocV2, error) {
	request := pkg.BulkDetailsRequest{Docid: packageNames}
	response, err := api.CallPostApiV2(BulkUrl+"?au=1", nil, strings.NewReader(request.String()))
	if err != nil {
		return nil, err
	}
	var details = []pkg.DocV2{}
	entries := response.Payload.BulkDetailsResponse.Entry
	for _, entry := range entries {
		if entry.Doc != nil {
			//noinspection GoVetCopyLock
			details = append(details, *entry.Doc)
		}
	}
	return details, nil
}

func (api *GooglePlayApi) Home(cat *string) ([]*pkg.DocV2, error) {

	path := HomeUrl + "?c=3&nocache_isui=true"
	if cat != nil {
		path += fmt.Sprintf("&cat=%s", url.QueryEscape(*cat))
	}
	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}
	if data := response.PreFetch; data != nil && len(data) > 0 {
		return data[0].Response.Payload.ListResponse.Doc, nil
	} else {
		return response.Payload.ListResponse.Doc, nil
	}
}

func (api *GooglePlayApi) Browse(cat, subCat *string) (*pkg.BrowseResponse, error) {
	path := BrowseUrl + "?c=3"
	if cat != nil {
		path += fmt.Sprintf("&cat=%s", url.QueryEscape(*cat))
	}
	if subCat != nil {
		path += fmt.Sprintf("&ctr=%s", url.QueryEscape(*subCat))
	}
	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}
	return response.Payload.BrowseResponse, nil
}

func (api *GooglePlayApi) List(cat string, subCat *string, nResults, offset *int) ([]*pkg.DocV2, error) {
	path := BrowseUrl + "?c=3" + fmt.Sprintf("&cat=%s", url.QueryEscape(cat))
	if subCat != nil {
		path += fmt.Sprintf("&ctr=%s", url.QueryEscape(*subCat))
	}
	if nResults != nil {
		path += fmt.Sprintf("&n=%d", *nResults)
	}
	if offset != nil {
		path += fmt.Sprintf("&o=%d", *offset)
	}
	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}
	var clusters []*pkg.DocV2

	if subCat != nil {
		for _, pf := range response.PreFetch {
			for _, cluster := range pf.Response.Payload.ListResponse.Doc {
				clusters = append(clusters, cluster.Child...)
			}
		}
	} else {
		for _, d := range response.Payload.ListResponse.Doc {
			for _, c := range d.Child {
				for _, a := range c.Child {
					clusters = append(clusters, a)
				}
			}
		}
	}
	return clusters, nil
}

func (api *GooglePlayApi) Reviews(packageName string, filterByDevice *bool, sort, nResults, offset *int) ([]*pkg.Review, error) {
	if filterByDevice == nil {
		tmp := false
		filterByDevice = &tmp
	}
	if sort == nil {
		tmp := 2
		sort = &tmp
	}

	path := ReviewsUrl + fmt.Sprintf("?doc=%s&sort=%d", url.QueryEscape(packageName), sort)

	if nResults != nil {
		path += fmt.Sprintf("&n=%d", *nResults)
	}
	if offset != nil {
		path += fmt.Sprintf("&o=%d", *offset)
	}
	if filterByDevice != nil {
		path += fmt.Sprintf("&dfil=1")
	}
	response, err := api.CallGetApiV2(path, nil, nil)
	if err != nil {
		return nil, err
	}

	return response.Payload.ReviewResponse.GetResponse.Review, nil
}

func (api *GooglePlayApi) deliverData(url string, cookies ...http.Cookie) (*DeliveryFile, error) {
	headers := api.getHeaders(false)
	response, err := Get(url, nil, &headers, api.Proxy, &cookies)
	if err != nil {
		return nil, err
	}
	totalSize := response.ContentLength
	chunkSize := 32 * (1 << 10)

	var buffer []byte
	buffer = make([]byte, chunkSize, 0)
	_, err = response.Body.Read(buffer)

	if err != io.EOF && err != nil {
		return nil, err
	}

	return &DeliveryFile{
		Data:      buffer,
		TotalSize: totalSize,
		ChunkSize: chunkSize,
	}, nil
}

/*
  packageName (str): app unique ID (usually starting with 'com.')
          @versionCode (int): version to download
          @offerType (*int): different type of downloads (mostly unused for apks)
          @downloadToken (*string): download token returned by 'purchase' API
      Returns:
          Dictionary containing apk data and a list of expansion files. As stated
          in android documentation, there can be at most 2 expansion files, one with
          main content, and one for patching the main content. Their names should
          follow this format:
          [main|patch].<expansion-version>.<package-name>.obb
          Data to build this name string is provided in the dict object. For more
          info check https://developer.android.com/google/play/expansion-files.html
*/
func (api *GooglePlayApi) Delivery(packageName string, versionCode *string, offerType *int, downloadToken *string, expansionFiles *bool) (*DeliveryResult, error) {
	if versionCode == nil {
		details, err := api.Details(packageName)
		if err != nil {
			return nil, err
		}
		tmp := strconv.Itoa(int(*details.Details.AppDetails.VersionCode))
		versionCode = &tmp
	}
	if offerType == nil {
		tmp := 1
		offerType = &tmp
	}
	if expansionFiles == nil {
		tmp := false
		expansionFiles = &tmp
	}

	params := map[string]string{"ot": strconv.Itoa(*offerType),
		"doc": packageName,
		"vc":  *versionCode,
	}
	if downloadToken != nil {
		params["dtok"] = *downloadToken
	}

	response, err := api.CallGetApiV2(DeliveryUrl, nil, &params)
	if err != nil {
		return nil, err
	}
	downloadUrl := response.Payload.DeliveryResponse.AppDeliveryData.DownloadUrl
	if downloadUrl == nil || *downloadUrl == "" {
		return nil, RequestError("app not purchased")
	} else {
		result := DeliveryResult{
			DocId:          packageName,
			AdditionalData: []DeliveryAdditionalData{},
			Splits:         []DeliveryResultSplit{},
		}

		rawCookie := response.Payload.DeliveryResponse.AppDeliveryData.DownloadAuthCookie[0]
		deliveryFile, err := api.deliverData(*downloadUrl, http.Cookie{Name: rawCookie.GetName(), Value: rawCookie.GetValue()})
		if err != nil {
			return nil, err
		}

		result.File = *deliveryFile

		for _, split := range response.Payload.DeliveryResponse.AppDeliveryData.Split {
			splitFile, err := api.deliverData(*split.DownloadUrl)
			if err != nil {
				return nil, err
			}

			result.Splits = append(result.Splits, DeliveryResultSplit{
				Name: *split.Name,
				File: *splitFile,
			})
		}
		if !* expansionFiles {
			return &result, nil
		}
		for _, obb := range response.Payload.DeliveryResponse.AppDeliveryData.AdditionalFile {
			var obbType string
			if *obb.FileType == 0 {
				obbType = "main"
			} else {
				obbType = "patch"
			}

			additionalData := DeliveryAdditionalData{
				Type:        obbType,
				VersionCode: strconv.Itoa(int(obb.GetVersionCode())),
				File:        DeliveryFile{},
			}
			result.AdditionalData = append(result.AdditionalData, additionalData)
		}
		return &result, nil

	}

}

func (api *GooglePlayApi) Download(packageName string, versionCode *string, offerType *int, expansionFiles *bool) (*DeliveryResult, error) {

	if versionCode == nil {
		details, err := api.Details(packageName)
		if err != nil {
			return nil, err
		}
		tmp := strconv.Itoa(int(*details.Details.AppDetails.VersionCode))
		versionCode = &tmp
	}
	if offerType == nil {
		tmp := 1
		offerType = &tmp
	}
	params := map[string]string{"ot": strconv.Itoa(*offerType),
		"doc": packageName,
		"vc":  *versionCode,
	}

	_, err := api.Log(packageName)
	if err != nil {
		return nil, err
	}

	response, err := api.CallPostFormApiV2(PurchaseUrl, params)
	if err != nil {
		return nil, err
	}
	return api.Delivery(packageName, versionCode, offerType, response.Payload.BuyResponse.DownloadToken, expansionFiles)
}

func (api *GooglePlayApi) Log(docId string) (*pkg.ResponseWrapper, error) {
	query := fmt.Sprintf("confirmFreeDownload?doc=%s", docId)
	timestamp := time.Now().Unix()

	request := pkg.LogRequest{
		DownloadConfirmationQuery: &query,
		Timestamp:                 &timestamp,
	}
	return api.CallPostApiV2(LogUrl, nil, strings.NewReader(request.String()))
}
