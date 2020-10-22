package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v4"
	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Все env переменные:
// PORT
// DATABASE_URL
// VK_SECRET_KEY
// RECAPTCHA_SECRET

var (
	vkSecretKey     = []byte(os.Getenv("VK_SECRET_KEY"))
	reCaptchaSecret = os.Getenv("RECAPTCHA_SECRET")
)

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

type ratingCounts [5]uint32

type ratingDayData struct {
	date   time.Time
	counts ratingCounts
}

type userData struct {
	rating        [7]ratingDayData
	lastTimeRated time.Time
}

var (
	users    = map[uint32]*userData{}
	usersMux sync.Mutex
)

const createUsersTableSQL = `CREATE TABLE IF NOT EXISTS users (
	vk_userid INT NOT NULL PRIMARY KEY,
	ratingCounts integer[5][7],
	ratingDates date[7]
);`

func main() {
	dbconn, err := pgx.Connect(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer dbconn.Close(context.Background())

	v, err := dbconn.Exec(context.Background(), createUsersTableSQL)
	zap.S().Info(v)
	if err != nil {
		panic(err)
	}

	port := os.Getenv("PORT")

	if port == "" {
		panic("$PORT must be set")
	}

	err = fasthttp.ListenAndServe(":"+port, func(ctx *fasthttp.RequestCtx) {
		requestHandler(ctx, dbconn)
	})
	if err != nil {
		panic(err)
	}
}

func requestHandler(ctx *fasthttp.RequestCtx, dbconn *pgx.Conn) {
	ctx.SetContentType("application/json; charset=utf8")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	var response *responseData
	switch string(ctx.URI().Path()) {
	case "/get_rating":
		response = handleGetRating(ctx, dbconn)
	case "/post_rating":
		response = handlePostRating(ctx, dbconn)
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
	Rating [7]ratingCounts `json:"rating"`
}

func handleGetRating(ctx *fasthttp.RequestCtx, dbconn *pgx.Conn) (response *responseData) {
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

	rating := [7]ratingDayData{}

	usersMux.Lock()
	user := users[reqData.UserID]
	if user != nil {
		rating = user.rating
	}
	usersMux.Unlock()

	responseRating := [7]ratingCounts{}

	tn := time.Now()
	for k, v := range rating {
		if tn.Sub(v.date) > time.Hour*24*7 {
			responseRating[k] = ratingCounts{0, 0, 0, 0, 0}
		} else {
			responseRating[k] = v.counts
		}
	}

	return &responseData{
		Data: &getRatingResData{
			Rating: responseRating,
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

func handlePostRating(ctx *fasthttp.RequestCtx, dbconn *pgx.Conn) (response *responseData) {
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

	usersMux.Lock()

	requesterUser := users[requesterUserID]
	if requesterUser == nil {
		requesterUser = new(userData)
		users[requesterUserID] = requesterUser
	}

	if tn.Sub(requesterUser.lastTimeRated) < time.Minute {
		usersMux.Unlock()
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

	wd := tn.Weekday()

	if tn.Sub(user.rating[wd].date) > time.Hour*24*7 {
		user.rating[wd].date = tn
		counts := ratingCounts{}
		counts[reqData.Rate-1]++
		user.rating[wd].counts = counts
	} else {
		user.rating[wd].counts[reqData.Rate-1]++
	}

	requesterUser.lastTimeRated = tn

	usersMux.Unlock()

	return &responseData{
		Data: &postRatingResData{
			Success: true,
		},
	}
}
