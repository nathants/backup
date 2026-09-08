package s3server

import (
	"encoding/xml"
	"net/http"
)

type s3Error struct {
	XMLName   xml.Name `xml:"Error"`
	Code      string   `xml:"Code"`
	Message   string   `xml:"Message"`
	RequestID string   `xml:"RequestId"`
	Resource  string   `xml:"Resource"`
}

func writeError(writer http.ResponseWriter, status int, code, message, requestID, resource string) {
	writer.Header().Set("Content-Type", "application/xml")
	writer.WriteHeader(status)
	_ = xml.NewEncoder(writer).Encode(s3Error{Code: code, Message: message, RequestID: requestID, Resource: resource})
}
