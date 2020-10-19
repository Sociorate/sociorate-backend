package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
)

var vkSecretKey = []byte(os.Getenv("VK_SECRET_KEY"))

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
	ctx.SetContentType("application/json; charset=utf8")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	var response *responseData
	switch string(ctx.Method()) {
	case "GET":
		response = handleGet(ctx)
	case "POST":
		response = handlePost(ctx)
	}

	if response == nil {
		return
	}

	resData, err := jsoniter.Marshal(response)
	if err != nil {
		zap.L().Error(err.Error())
		return
	}

	_, err = ctx.Write(resData)
	if err != nil {
		zap.L().Error(err.Error())
	}
}

type ratingData [5]uint32

var usersRatings = map[uint32]ratingData{}

type getRatingReqData struct {
	UserID uint32 `json:"userid"`
}

type getRatingResData struct {
	Rating ratingData `json:"rating"`
}

type postRatingReqData struct {
	UserID         uint32 `json:"userid"`
	Rate           uint8  `json:"rate"`
	ReCaptchaToken string `json:"recaptcha_token"`
	URLParams      struct {
		Params string `json:"params"`
		Sign   string `json:"sign"`
	} `json:"url_params"`
}

type postRatingResData struct {
	Ok bool `json:"ok"`
}

type errData struct {
	Code        int    `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
}

type responseData struct {
	Err  *errData    `json:"error,omitempty"`
	Data interface{} `json:"data,omitempty"`
}

func handleGet(ctx *fasthttp.RequestCtx) (response *responseData) {
	reqData := new(getRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &errData{
				Code:        1234,
				Description: "Error occured while unmarshall your json",
			},
		}
	}

	return &responseData{
		Data: &getRatingResData{
			Rating: usersRatings[reqData.UserID],
		},
	}
}

func handlePost(ctx *fasthttp.RequestCtx) (response *responseData) {
	reqData := new(postRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &errData{
				Code:        1234,
				Description: "Error occured while unmarshall your json",
			},
		}
	}

	h := hmac.New(sha256.New, vkSecretKey)
	h.Write([]byte(reqData.URLParams.Params))

	genSign := base64.StdEncoding.EncodeToString(h.Sum(nil))
	genSign = strings.ReplaceAll(genSign, "+", "-")
	genSign = strings.ReplaceAll(genSign, "/", "/")

	println(genSign)
	println(reqData.URLParams.Sign)
	return nil

	ctx.WriteString(`{ "data": {} }`)

	return &responseData{
		Data: &postRatingResData{
			Ok: true,
		},
	}
}
