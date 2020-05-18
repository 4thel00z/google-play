package google_play

type DeliveryFile struct {
	Data      []byte
	TotalSize int64
	ChunkSize int
}

type DeliveryResultSplit struct {
	Name string
	File DeliveryFile
}
type DeliveryAdditionalData struct {
	Type        string
	VersionCode string
	File        DeliveryFile
}
type DeliveryResult struct {
	DocId          string
	File           DeliveryFile
	Splits         []DeliveryResultSplit
	AdditionalData []DeliveryAdditionalData
}
