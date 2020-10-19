package main

import (
	"bytes"
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

var (
	vkSecretKey     = []byte(os.Getenv("VK_SECRET_KEY"))
	reCaptchaSecret = os.Getenv("RECAPTCHA_SECRET")
)

type ratingData [5]uint32

var usersRatings = map[uint32]ratingData{}

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
	switch string(ctx.URI().Path()) {
	case "/get_rating":
		response = handleGetRating(ctx)
	case "/post_rating":
		response = handlePostRating(ctx)
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

type responseErrData struct {
	Code        int    `json:"code,omitempty"`
	Description string `json:"description,omitempty"`
}

type responseData struct {
	Err  *responseErrData `json:"error,omitempty"`
	Data interface{}      `json:"data,omitempty"`
}

type getRatingReqData struct {
	UserID uint32 `json:"userid"`
}

type getRatingResData struct {
	Rating ratingData `json:"rating"`
}

func handleGetRating(ctx *fasthttp.RequestCtx) (response *responseData) {
	reqData := new(getRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
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

var fasthhtpClient = &fasthttp.Client{
	NoDefaultUserAgentHeader: true,
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
	Success bool `json:"ok"`
}

// TODO: кулдаун, проверка на оценивание самого себя
func handlePostRating(ctx *fasthttp.RequestCtx) (response *responseData) {
	reqData := new(postRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        1234,
				Description: "Error occured while unmarshall your json",
			},
		}
	}

	h := hmac.New(sha256.New, vkSecretKey)
	h.Write([]byte(reqData.URLParams.Params))

	genSign := base64.RawStdEncoding.EncodeToString(h.Sum(nil))
	genSign = strings.ReplaceAll(genSign, "+", "-")
	genSign = strings.ReplaceAll(genSign, "/", "_")

	if genSign != reqData.URLParams.Sign {
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Sign/urlparams is not correct",
			},
		}
	}

	a := bytes.Split(ctx.Request.Header.Peek("X-Forwarded-For"), []byte(","))
	remoteIP := strings.TrimSpace(string(a[len(a)-1]))

	postArgs := ctx.PostArgs()
	postArgs.Set("secret", reCaptchaSecret)
	postArgs.Set("respone", reqData.ReCaptchaToken)
	postArgs.Set("remoteip", remoteIP)

	_, body, err := fasthhtpClient.Post(nil, "https://www.google.com/recaptcha/api/siteverify", postArgs)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	if !jsoniter.Get(body, "success").ToBool() {
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Invalid ReCAPTCHA token",
			},
		}
	}

	if reqData.Rate > 5 || reqData.Rate == 0 {
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Rate can only be 5, 3, 2 or 1",
			},
		}
	}

	rating := usersRatings[reqData.UserID]
	rating[reqData.Rate-1]++
	usersRatings[reqData.UserID] = rating

	return &responseData{
		Data: &postRatingResData{
			Success: true,
		},
	}
}
