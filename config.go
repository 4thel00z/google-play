package google_play

import (
	"encoding/json"
	"fmt"
	"github.com/4thel00z/google-play/pkg"
	"regexp"
	"strings"
	"time"
)

type Device struct {
	Locale               string
	Timezone             string
	Platforms            string      `json:"platforms"`
	Name                 string      `json:"name"`
	UserReadableName     []string    `json:"userreadablename"`
	BuildHardware        string      `json:"build.hardware"`
	BuildRadio           string      `json:"build.radio"`
	BuildBootloader      string      `json:"build.bootloader"`
	BuildFingerprint     string      `json:"build.fingerprint"`
	BuildBrand           string      `json:"build.brand"`
	BuildDevice          string      `json:"build.device"`
	BuildVersionSdkInt   string      `json:"build.version.sdk_int"`
	BuildModel           interface{} `json:"build.model"`
	BuildManufacturer    string      `json:"build.manufacturer"`
	BuildProduct         string      `json:"build.product"`
	BuildId              string      `json:"build.id"`
	BuildVersionRelease  string      `json:"build.version.release"`
	Touchscreen          string      `json:"touchscreen"`
	Keyboard             string      `json:"keyboard"`
	Navigation           string      `json:"navigation"`
	ScreenLayout         string      `json:"screenlayout"`
	HasHardKeyboard      string      `json:"hashardkeyboard"`
	HasFiveWayNavigation string      `json:"hasfivewaynavigation"`
	GlVersion            string      `json:"gl.version"`
	ScreenDensity        string      `json:"screen.density"`
	ScreenWidth          string      `json:"screen.width"`
	ScreenHeight         string      `json:"screen.height"`
	SharedLibraries      string      `json:"sharedlibraries"`
	Features             string      `json:"features"`
	Locales              string    `json:"locales"`
	GsfVersion           string      `json:"gsf.version"`
	VendingVersion       string      `json:"vending.version"`
	VendingVersionString []string    `json:"vending.versionstring"`
	CellOperator         string      `json:"celloperator"`
	SimOperator          string      `json:"simoperator"`
	Client               string      `json:"client"`
	GlExtensions         string      `json:"gl.extensions"`
	Roaming              string      `json:"roaming"`
}

type DeviceName struct {
	CodeName     string `json:"code_name"`
	ReadableName string `json:"readable_name"`
}
type Devices []Device

func ParseDevices(path string) (map[string]Device, error) {
	var (
		devices   Devices
		deviceMap = map[string]Device{}
	)

	content, err := readAll(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(content, &devices)
	if err != nil {
		return nil, err
	}
	for _, device := range devices {
		deviceMap[device.Name] = device
	}
	return deviceMap, nil
}

const (
	DfeTargets   = "CAEScFfqlIEG6gUYogFWrAISK1WDAg+hAZoCDgIU1gYEOIACFkLMAeQBnASLATlASUuyAyqCAjY5igOMBQzfA/IClwFbApUC4ANbtgKVAS7OAX8YswHFBhgDwAOPAmGEBt4OfKkB5weSB5AFASkiN68akgMaxAMSAQEBA9kBO7UBFE1KVwIDBGs3go6BBgEBAgMECQgJAQIEAQMEAQMBBQEBBAUEFQYCBgUEAwMBDwIBAgOrARwBEwMEAg0mrwESfTEcAQEKG4EBMxghChMBDwYGASI3hAEODEwXCVh/EREZA4sBYwEdFAgIIwkQcGQRDzQ2fTC2AjfVAQIBAYoBGRg2FhYFBwEqNzACJShzFFblAo0CFxpFNBzaAd0DHjIRI4sBJZcBPdwBCQGhAUd2A7kBLBVPngEECHl0UEUMtQETigHMAgUFCc0BBUUlTywdHDgBiAJ+vgKhAU0uAcYCAWQ/5ALUAw1UwQHUBpIBCdQDhgL4AY4CBQICjARbGFBGWzA1CAEMOQH+BRAOCAZywAIDyQZ2MgM3BxsoAgUEBwcHFia3AgcGTBwHBYwBAlcBggFxSGgIrAEEBw4QEqUCASsWadsHCgUCBQMD7QICA3tXCUw7ugJZAwGyAUwpIwM5AwkDBQMJA5sBCw8BNxBVVBwVKhebARkBAwsQEAgEAhESAgQJEBCZATMdzgEBBwG8AQQYKSMUkAEDAwY/CTs4/wEaAUt1AwEDAQUBAgIEAwYEDx1dB2wGeBFgTQ"
	GooglePubkey = "AAAAgMom/1a/v0lblO2Ubrt60J2gcuXSljGFQXgcyZWveWLEwo6prwgi3iJIZdodyhKZQrNWp5nKJ3srRXcUW+F1BD3baEVGcmEgqaLZUNBjm057pKRI16kB0YppeGx5qIQ5QjKzsR8ETQbKLNWgRY0QRNVz34kMJR3P/LgHax/6rmf5AAAAAwEAAQ=="
	AccountType  = "HOSTED_OR_GOOGLE"
)

type InvalidLocaleError struct {
	value string
}

func (l InvalidLocaleError) Error() string {
	return l.value
}

type InvalidTimezoneError struct {
	value string
}

func (l InvalidTimezoneError) Error() string {
	return l.value
}

func (devices Devices) GetDevicesCodeNames() []string {
	var names []string
	for _, device := range devices {
		names = append(names, device.Name)
	}
	return names
}

func (devices Devices) GetDevicesReadableNames() []DeviceName {
	var names []DeviceName
	for _, device := range devices {
		names = append(names, DeviceName{
			CodeName:     device.Name,
			ReadableName: strings.Join(device.UserReadableName, ""),
		})
	}
	return names
}

func (self Device) setLocale(locale string) error {

	if locale == "" {
		return InvalidLocaleError{value: "locale is empty"}
	}

	pattern := regexp.MustCompile(`[a-z]{2}\_[A-Z]{2}`)

	if !pattern.MatchString(locale) {
		return InvalidLocaleError{value: "locale does not match the regex"}
	}

	self.Locale = locale
	return nil
}

func (self Device) setTimezone(timezone string) error {

	if timezone == "" {
		return InvalidTimezoneError{value: "locale is empty"}
	}

	self.Timezone = timezone
	return nil
}

func (self Device) getBaseHeaders() map[string]string {

	locale := strings.ReplaceAll(self.Locale, "_", "-")

	return map[string]string{
		"Accept-Language":       locale,
		"X-DFE-Encoded-Targets": DfeTargets,
		"User-Agent":            self.getUserAgent(),
		"X-DFE-Client-Id":       "am-android-google",
		"X-DFE-MCCMNC":          self.CellOperator,
		"X-DFE-Network-Type":    "4",
		"X-DFE-Content-Filters": "",
		"X-DFE-Request-Params":  "timeoutMs=4000"}

}
func (self Device) getUploadHeaders() map[string]string {
	result := self.getBaseHeaders()
	additionalHeaders := map[string]string{
		"X-DFE-Enabled-Experiments":     "cl:billing.select_add_instrument_by_default",
		"X-DFE-Unsupported-Experiments": "nocache:billing.use_charging_poller,market_emails,buyer_currency,prod_baseline,checkin.set_asset_paid_app_field,shekel_test,content_ratings,buyer_currency_in_app,nocache:encrypted_apk,recent_changes",
		"X-DFE-SmallestScreenWidthDp":   "320",
		"X-DFE-Filter-Level":            "3",
	}
	for k, v := range additionalHeaders {
		result[k] = v
	}

	return result
}

func (self Device) getLoginParams(email, encryptedPassword string) map[string]string {
	return map[string]string{
		"Email":                        email,
		"EncryptedPasswd":              encryptedPassword,
		"add_account":                  "1",
		"accountType":                  AccountType,
		"google_play_services_version": self.GsfVersion,
		"has_permission":               "1",
		"source":                       "android",
		"device_country":               string([]rune(self.Locale)[0:2]),
		"lang":                         self.Locale,
		"client_sig":                   "38918a453d07199354f8b19af05ec6562ced5788",
		"callerSig":                    "38918a453d07199354f8b19af05ec6562ced5788",
	}
}

func (self Device) getAuthHeader(Gsfid int) map[string]string {
	result := map[string]string{
		"User-Agent": fmt.Sprintf("GoogleAuth/1.4 (%s %s)", self.BuildDevice, self.BuildId),
	}

	if Gsfid <= 0 {
		result["device"] = fmt.Sprintf("%x", Gsfid)
	}

	return result
}

func (self Device) getUserAgent() string {

	versionString := strings.Join(self.VendingVersionString, " ")
	if versionString == "" {
		versionString = "8.4.19.V-all [0] [FP] 175058788"
	}

	template := "Android-Finsky/%s (api=3," +
		"versionCode=%s," +
		"sdk=%s," +
		"device=%s," +
		"hardware=%s," +
		"product=%s," +
		"platformVersionRelease=%s," +
		"model=%s," +
		"buildId=%s," +
		"isWideScreen=0," +
		"supportedAbis=%s)"

	var buildModel string
	switch self.BuildModel.(type) {
	case string:
		{
			buildModel = self.BuildModel.(string)
		}

	default:
	case []string:
		{
			buildModel = strings.Join(self.BuildModel.([]string), " ")
		}
	}

	return fmt.Sprintf(template,
		versionString,
		self.VendingVersion,
		self.BuildVersionSdkInt,
		self.Name,
		self.BuildHardware,
		self.BuildProduct,
		self.BuildVersionRelease,
		buildModel,
		self.BuildId,
		strings.ReplaceAll(self.Platforms, ",", ";"))
}

func (self Device) GetAndroidCheckinRequest() (*pkg.AndroidCheckinRequest, error) {
	request := pkg.AndroidCheckinRequest{}
	id := int64(0)
	version := int32(3)
	fragment := int32(0)
	checkin, err := self.GetAndroidCheckin()
	if err != nil {
		return nil, err
	}
	request.Id = &id
	request.Checkin = checkin
	request.Locale = &self.Locale
	request.TimeZone = &self.Timezone
	request.Version = &version
	config, err := self.GetDeviceConfig()
	if err != nil {
		return nil, err
	}
	request.DeviceConfiguration = config
	request.Fragment = &fragment
	return &request, nil
}

func (self Device) GetDeviceConfig() (*pkg.DeviceConfigurationProto, error) {
	sharedLibs := strings.Split(self.SharedLibraries, ",")
	features := strings.Split(self.Features, ",")
	locales := strings.Split(self.Locales, ",")
	glExtensions := strings.Split(self.GlExtensions, ",")
	platforms := strings.Split(self.Platforms, ",")
	hasFiveWayNavigation := self.HasFiveWayNavigation == "true"
	HasHardKeyboard := self.HasHardKeyboard == "true"
	touchscreen, err := parsei32(self.Touchscreen)
	if err != nil {
		return nil, err
	}
	keyboard, err := parsei32(self.Keyboard)
	if err != nil {
		return nil, err
	}
	navigation, err := parsei32(self.Navigation)
	if err != nil {
		return nil, err
	}

	screenLayout, err := parsei32(self.ScreenLayout)
	if err != nil {
		return nil, err
	}

	screenDensity, err := parsei32(self.ScreenDensity)
	if err != nil {
		return nil, err
	}
	screenWidth, err := parsei32(self.ScreenWidth)
	if err != nil {
		return nil, err
	}

	screenHeight, err := parsei32(self.ScreenHeight)
	if err != nil {
		return nil, err
	}

	glVersion, err := parsei32(self.GlVersion)
	if err != nil {
		return nil, err
	}

	config := pkg.DeviceConfigurationProto{}
	config.TouchScreen = touchscreen
	config.Keyboard = keyboard
	config.Navigation = navigation
	config.ScreenLayout = screenLayout
	config.HasHardKeyboard = &HasHardKeyboard
	config.HasFiveWayNavigation = &hasFiveWayNavigation
	config.ScreenDensity = screenDensity
	config.ScreenWidth = screenWidth
	config.ScreenHeight = screenHeight
	config.GlEsVersion = glVersion

	config.NativePlatform = platforms
	config.SystemSharedLibrary = sharedLibs
	config.SystemAvailableFeature = features
	config.SystemSupportedLocale = locales
	config.GlExtension = glExtensions

	return &config, nil
}

func (self Device) GetAndroidBuild() (*pkg.AndroidBuildProto, error) {
	buildVersionSdkInt, err := parsei32(self.BuildVersionSdkInt)
	if err != nil {
		return nil, err
	}
	gsfVersion, err := parsei32(self.GsfVersion)
	if err != nil {
		return nil, err
	}
	otaInstalled := false
	now := time.Now().Unix() / 1000
	var buildModel string
	switch self.BuildModel.(type) {
	case string:
		{
			buildModel = self.BuildModel.(string)
		}

	default:
	case []string:
		{
			buildModel = strings.Join(self.BuildModel.([]string), " ")
		}
	}
	androidBuild := pkg.AndroidBuildProto{}
	androidBuild.Id = &self.BuildFingerprint
	androidBuild.Product = &self.BuildHardware
	androidBuild.Carrier = &self.BuildBrand
	androidBuild.Radio = &self.BuildRadio
	androidBuild.Bootloader = &self.BuildBootloader
	androidBuild.Device = &self.BuildDevice
	androidBuild.SdkVersion = buildVersionSdkInt
	androidBuild.Model = &buildModel
	androidBuild.Manufacturer = &self.BuildManufacturer
	androidBuild.BuildProduct = &self.BuildProduct
	androidBuild.Client = &self.Client
	androidBuild.OtaInstalled = &otaInstalled
	androidBuild.Timestamp = &now
	androidBuild.GoogleServices = gsfVersion
	return &androidBuild, nil
}
func (self Device) GetAndroidCheckin() (*pkg.AndroidCheckinProto, error) {

	androidBuild, err := self.GetAndroidBuild()
	if err != nil {
		return nil, err
	}
	androidCheckin := pkg.AndroidCheckinProto{}
	androidCheckin.Build = androidBuild
	lastCheckinMs := int64(0)
	userNumber := int32(0)
	androidCheckin.LastCheckinMsec = &lastCheckinMs
	androidCheckin.CellOperator = &self.CellOperator
	androidCheckin.SimOperator = &self.SimOperator
	androidCheckin.Roaming = &self.Roaming
	androidCheckin.UserNumber = &userNumber
	return &androidCheckin, nil
}
