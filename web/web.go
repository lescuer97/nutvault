package web

import (
	"net/http"

	"google.golang.org/grpc"
)

func RunHTTPServer(addr string, conn *grpc.ClientConn) error {
	router := NewRouter()
	return http.ListenAndServe(addr, router)
}
