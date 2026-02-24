package s3server

import (
	"encoding/xml"
	"net/http"
)

type s3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestId string   `xml:"RequestId"`
	Resource  string   `xml:"Resource"`
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	payload := s3Error{Code: code, Message: message}
	_ = xml.NewEncoder(w).Encode(payload)
}
