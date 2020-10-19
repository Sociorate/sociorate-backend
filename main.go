package main

import (
	"fmt"
	"os"

	"github.com/valyala/fasthttp"
)

var vkSecretKey = os.Getenv("VK_SECRET_KEY")

func main() {
	port := os.Getenv("PORT")

	if port == "" {
		panic("$PORT must be set")
	}

	err := fasthttp.ListenAndServe(":"+port, requestHandler)
	if err != nil {
		panic(fmt.Errorf("Error in ListenAndServe: %s", err))
	}
}

func requestHandler(ctx *fasthttp.RequestCtx) {
	switch string(ctx.Method()) {
	case "GET":
		ctx.WriteString(`{ "data": { "rating": [1, 2, 4, 9, 15] } }`)
	case "POST":
		ctx.WriteString(`{ "data": {} }`)
	}

	ctx.SetContentType("application/json; charset=utf8")
}
