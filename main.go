package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	vkSecretKey     = []byte(os.Getenv("VK_SECRET_KEY"))
	reCaptchaSecret = os.Getenv("RECAPTCHA_SECRET")
)

type ratingData [7][5]uint8

type userData struct {
	rating        ratingData
	lastTimeRated time.Time
}

var users = map[uint32]*userData{}

func init() {
	logger, err := zap.Config{
		Level:       zap.NewAtomicLevelAt(zap.InfoLevel),
		Development: false,
		Encoding:    "console",
		EncoderConfig: zapcore.EncoderConfig{
			NameKey: "name",
			// TimeKey:        "time",
			LevelKey:       "level",
			MessageKey:     "message",
			CallerKey:      "caller",
			StacktraceKey:  "stacktrace",
			FunctionKey:    "function",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.TimeEncoderOfLayout(""),
			EncodeDuration: nil,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},
		OutputPaths:      []string{"stdout"},
		ErrorOutputPaths: []string{"stderr"},
	}.Build()
	if err != nil {
		panic(err)
	}

	zap.ReplaceGlobals(logger)
}

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

	rating := ratingData{}

	user := users[reqData.UserID]
	if user != nil {
		rating = user.rating
	}

	return &responseData{
		Data: &getRatingResData{
			Rating: rating,
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

	u, err := url.Parse("?" + reqData.URLParams.Params)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        1234,
				Description: "Malformed url params",
			},
		}
	}

	vkTs, err := strconv.ParseInt(u.Query().Get("vk_ts"), 10, 64)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Unable to parse vk_user_id form url params",
			},
		}
	}

	tn := time.Now()

	if tn.Sub(time.Unix(vkTs, 0)) > time.Hour*24 {
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Your vk_ts is too little, it was 24 hours ago",
			},
		}
	}

	requesterUserID64, err := strconv.ParseUint(u.Query().Get("vk_user_id"), 10, 32)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Unable to parse vk_user_id form url params",
			},
		}
	}

	requesterUserID := uint32(requesterUserID64)

	if requesterUserID == reqData.UserID {
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "You can't rate yourself",
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
	postArgs.Set("response", reqData.ReCaptchaToken)
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

	requesterUser := users[requesterUserID]
	if requesterUser == nil {
		requesterUser = new(userData)
		users[requesterUserID] = requesterUser
	}

	if tn.Sub(requesterUser.lastTimeRated) < time.Minute {
		return &responseData{
			Err: &responseErrData{
				Code:        98765,
				Description: "You can rate only once a minute",
			},
		}
	}

	user := users[reqData.UserID]
	if user == nil {
		user = new(userData)
		users[reqData.UserID] = user
	}

	wd := tn.Weekday() - 1
	if wd == -1 {
		wd = time.Sunday
	}

	user.rating[wd][reqData.Rate-1]++

	users[reqData.UserID] = user

	requesterUser.lastTimeRated = tn

	return &responseData{
		Data: &postRatingResData{
			Success: true,
		},
	}
}
