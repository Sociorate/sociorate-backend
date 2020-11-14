package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/url"
	"os"
	"strconv"
	"strings"
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
			NameKey:    "name",
			TimeKey:    "time",
			LevelKey:   "level",
			MessageKey: "message",
			CallerKey:  "caller",
			// StacktraceKey:  "stacktrace",
			FunctionKey:    "function",
			LineEnding:     zapcore.DefaultLineEnding,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeTime:     zapcore.ISO8601TimeEncoder,
			EncodeDuration: zapcore.NanosDurationEncoder,
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

const sqlCreateTableUsers = `CREATE TABLE IF NOT EXISTS users (
    vk_user_id INTEGER UNIQUE NOT NULL PRIMARY KEY,
    remaining_user_rates SMALLINT DEFAULT 9 NOT NULL,
    user_rates_restore_time TIMESTAMP DEFAULT NOW() NOT NULL,
    rating_count_5 INTEGER DEFAULT 0 NOT NULL,
    rating_count_4 INTEGER DEFAULT 0 NOT NULL,
    rating_count_3 INTEGER DEFAULT 0 NOT NULL,
    rating_count_2 INTEGER DEFAULT 0 NOT NULL,
	rating_count_1 INTEGER DEFAULT 0 NOT NULL
);`

const sqlCreateTableUserRatesTimes = `CREATE TABLE IF NOT EXISTS user_rates_times (
    vk_user_id INTEGER NOT NULL,
	target_vk_user_id INTEGER NOT NULL,
	remaining_user_target_rates INTEGER DEFAULT 2 NOT NULL,
	user_target_rates_restore_time TIMESTAMP DEFAULT NOW() NOT NULL,
	PRIMARY KEY (vk_user_id, target_vk_user_id)
);`

func main() {
	zap.L().Info("Starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbconn, err := pgx.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer dbconn.Close(ctx)

	_, err = dbconn.Exec(ctx, sqlCreateTableUsers)
	if err != nil {
		panic(err)
	}
	_, err = dbconn.Exec(ctx, sqlCreateTableUserRatesTimes)
	if err != nil {
		panic(err)
	}

	s := &fasthttp.Server{
		Handler: func(ctx *fasthttp.RequestCtx) {
			handleRequest(ctx, dbconn)
		},
		NoDefaultServerHeader: true,
	}

	zap.L().Info("Listening and serving")

	err = s.ListenAndServeTLS(":"+os.Getenv("PORT"), "cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}
}

func handleRequest(ctx *fasthttp.RequestCtx, dbconn *pgx.Conn) {
	zap.L().Info(ctx.String())

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

	ctx.SetContentType("application/json; charset=utf8")
	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")
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
	VKUserID uint32 `json:"vk_user_id"`
}

type getRatingResData struct {
	RatingCounts [5]uint32 `json:"rating_counts"`
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

	ratingCounts := [5]uint32{}

	err = dbconn.QueryRow(ctx, "SELECT rating_count_5, rating_count_4, rating_count_3, rating_count_2, rating_count_1 FROM users WHERE vk_user_id = $1", reqData.VKUserID).Scan(&ratingCounts[4], &ratingCounts[3], &ratingCounts[2], &ratingCounts[1], &ratingCounts[0])
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	return &responseData{
		Data: &getRatingResData{
			RatingCounts: ratingCounts,
		},
	}
}

type postRatingReqData struct {
	VKUserID       uint32 `json:"vk_user_id"`
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

var fasthttpClient = &fasthttp.Client{
	NoDefaultUserAgentHeader: true,
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
				Description: "Your vk_ts is expired, it was 24 hours ago",
			},
		}
	}

	requesterVKUserID64, err := strconv.ParseUint(u.Query().Get("vk_user_id"), 10, 32)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        666,
				Description: "Unable to parse vk_user_id form url params",
			},
		}
	}

	requesterVKUserID := uint32(requesterVKUserID64)

	if requesterVKUserID == reqData.VKUserID {
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

	_, body, err := fasthttpClient.Post(nil, "https://www.google.com/recaptcha/api/siteverify", postArgs)
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

	var (
		remainingUserRates   int16
		userRatesRestoreTime time.Time
	)

	err = dbconn.QueryRow(ctx, "SELECT remaining_user_rates, user_rates_restore_time FROM users WHERE vk_user_id = $1;", requesterVKUserID).Scan(&remainingUserRates, &userRatesRestoreTime)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	if userRatesRestoreTime.Sub(tn) <= 0 {
		remainingUserRates = 9

		_, err = dbconn.Exec(ctx, "INSERT INTO users (vk_user_id, remaining_user_rates, user_rates_restore_time) VALUES ($1, 9, NOW() + INTERVAL '1 DAY') ON CONFLICT (vk_user_id) DO UPDATE SET remaining_user_rates = EXCLUDED.remaining_user_rates, user_rates_restore_time = EXCLUDED.user_rates_restore_time;", requesterVKUserID)
		if err != nil {
			zap.L().Error(err.Error())
			return &responseData{
				Err: &responseErrData{
					Code:        777,
					Description: "Internal error",
				},
			}
		}
	}

	if remainingUserRates <= 0 {
		return &responseData{
			Err: &responseErrData{
				Code:        98765,
				Description: "You can rate only 9 times per 24 hours",
			},
		}
	}

	var (
		remainingUserTargetRates   int16
		userTargetRatesRestoreTime time.Time
	)

	err = dbconn.QueryRow(ctx, "SELECT remaining_user_target_rates, user_target_rates_restore_time FROM user_rates_times WHERE (vk_user_id = $1 AND target_vk_user_id = $2);", requesterVKUserID, reqData.VKUserID).Scan(&remainingUserTargetRates, &userTargetRatesRestoreTime)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	if userTargetRatesRestoreTime.Sub(tn) <= 0 {
		remainingUserTargetRates = 2

		_, err = dbconn.Exec(ctx, "INSERT INTO user_rates_times (vk_user_id, target_vk_user_id, remaining_user_target_rates, user_target_rates_restore_time) VALUES ($1, $2, 2, NOW() + INTERVAL '1 DAY') ON CONFLICT (vk_user_id, target_vk_user_id) DO UPDATE SET remaining_user_target_rates = EXCLUDED.remaining_user_target_rates, user_target_rates_restore_time = EXCLUDED.user_target_rates_restore_time;", requesterVKUserID, reqData.VKUserID)
		if err != nil {
			zap.L().Error(err.Error())
			return &responseData{
				Err: &responseErrData{
					Code:        777,
					Description: "Internal error",
				},
			}
		}
	}

	if remainingUserTargetRates <= 0 {
		return &responseData{
			Err: &responseErrData{
				Code:        4321,
				Description: "You can rate one user only 2 times per 24 hours",
			},
		}
	}

	var ratingCountColumnName string
	switch reqData.Rate {
	case 5:
		ratingCountColumnName = "rating_count_5"
	case 4:
		ratingCountColumnName = "rating_count_4"
	case 3:
		ratingCountColumnName = "rating_count_3"
	case 2:
		ratingCountColumnName = "rating_count_2"
	case 1:
		ratingCountColumnName = "rating_count_1"
	}

	_, err = dbconn.Exec(ctx, "INSERT INTO users (vk_user_id, "+ratingCountColumnName+") VALUES ($1, 1) ON CONFLICT (vk_user_id) DO UPDATE SET "+ratingCountColumnName+" = (SELECT "+ratingCountColumnName+" FROM users WHERE vk_user_id = $1) + 1;", reqData.VKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	_, err = dbconn.Exec(ctx, "INSERT INTO users (vk_user_id, remaining_user_rates) VALUES ($1, 8) ON CONFLICT (vk_user_id) DO UPDATE SET remaining_user_rates = (SELECT remaining_user_rates FROM users WHERE vk_user_id = $1) - 1;", requesterVKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	_, err = dbconn.Exec(ctx, "INSERT INTO user_rates_times (vk_user_id, target_vk_user_id, remaining_user_target_rates) VALUES ($1, $2, 1) ON CONFLICT (vk_user_id, target_vk_user_id) DO UPDATE SET remaining_user_target_rates = (SELECT remaining_user_target_rates FROM user_rates_times WHERE (vk_user_id = $1 AND target_vk_user_id = $2)) - 1;", requesterVKUserID, reqData.VKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				Code:        777,
				Description: "Internal error",
			},
		}
	}

	return &responseData{
		Data: &postRatingResData{
			Success: true,
		},
	}
}
