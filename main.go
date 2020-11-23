package main

import (
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
	"github.com/jackc/pgx/v4/pgxpool"
	jsoniter "github.com/json-iterator/go"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Все env переменные:
// PORT
// DATABASE_URL
// VK_SECRET_KEY
// VK_SERVICE_KEY

var (
	vkSecretKey  = []byte(os.Getenv("VK_SECRET_KEY"))
	vkServiceKey = os.Getenv("VK_SERVICE_KEY")
)

var fasthttpClient = &fasthttp.Client{
	NoDefaultUserAgentHeader: true,
}

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

func initDatabase(ctx context.Context, dbpool *pgxpool.Pool) {
	dbconn, err := dbpool.Acquire(ctx)
	if err != nil {
		panic(err)
	}
	defer dbconn.Release()

	_, err = dbconn.Exec(ctx, sqlCreateTableUsers)
	if err != nil {
		panic(err)
	}
	_, err = dbconn.Exec(ctx, sqlCreateTableUserRatesTimes)
	if err != nil {
		panic(err)
	}
}

type fasthttpZapLogger struct{}

func (fasthttpZapLogger) Printf(format string, args ...interface{}) {
	zap.S().Infof(format, args...)
}

func main() {
	zap.L().Info("Starting...")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dbpool, err := pgxpool.Connect(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		panic(err)
	}
	defer dbpool.Close()

	initDatabase(ctx, dbpool)

	s := &fasthttp.Server{
		Handler: fasthttp.TimeoutHandler(
			func(ctx *fasthttp.RequestCtx) {
				handleRequest(ctx, dbpool)
			},
			time.Second*15,
			`{"error":{"error_code":777,"error_msg":"Internal error"}`,
		),

		NoDefaultServerHeader: true,
		MaxRequestBodySize:    1024,
		Logger:                new(fasthttpZapLogger),
	}

	zap.L().Info("Listening and serving")

	err = s.ListenAndServeTLS(":"+os.Getenv("PORT"), "cert.pem", "key.pem")
	if err != nil {
		panic(err)
	}
}

func handleRequest(ctx *fasthttp.RequestCtx, dbpool *pgxpool.Pool) {
	zap.L().Info(
		"request",
		zap.String("remote_ip", ctx.RemoteIP().String()),
		zap.Uint64("conn_id", ctx.ConnID()),
		zap.Uint64("id", ctx.ID()),
		zap.ByteString("method", ctx.Method()),
		zap.ByteString("request_uri", ctx.RequestURI()),
		zap.ByteString("x_forwarded_for_header", ctx.Request.Header.Peek("X-Forwarded-For")),
		zap.ByteString("body", ctx.Request.Body()),
	)

	ctx.Response.Header.Set("Access-Control-Allow-Origin", "*")

	var response *responseData

	switch string(ctx.URI().Path()) {
	case "/get_rating":
		response = handleGetRating(ctx, dbpool)
	case "/post_rating":
		response = handlePostRating(ctx, dbpool)
	case "/vk_users_get":
		response = handleVKUsersGet(ctx)
	}

	if response == nil {
		return
	}

	ctx.SetContentType("application/json; charset=utf8")

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
	ErrorCode int    `json:"error_code,omitempty"`
	ErrorMsg  string `json:"error_msg,omitempty"`
}

type responseData struct {
	Err      *responseErrData `json:"error,omitempty"`
	Response interface{}      `json:"response,omitempty"`
}

type getRatingReqData struct {
	VKUserID uint32 `json:"vk_user_id"`
}

type getRatingResData struct {
	RatingCounts [5]uint32 `json:"rating_counts"`
}

func handleGetRating(ctx *fasthttp.RequestCtx, dbpool *pgxpool.Pool) (response *responseData) {
	reqData := new(getRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 1234,
				ErrorMsg:  "Error occured while unmarshall your json",
			},
		}
	}

	ratingCounts := [5]uint32{}

	err = dbpool.QueryRow(ctx, "SELECT rating_count_5, rating_count_4, rating_count_3, rating_count_2, rating_count_1 FROM users WHERE vk_user_id = $1", reqData.VKUserID).Scan(&ratingCounts[4], &ratingCounts[3], &ratingCounts[2], &ratingCounts[1], &ratingCounts[0])
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	return &responseData{
		Response: &getRatingResData{
			RatingCounts: ratingCounts,
		},
	}
}

type postRatingReqData struct {
	VKUserID  uint32 `json:"vk_user_id"`
	Rate      uint8  `json:"rate"`
	URLParams struct {
		Params string `json:"params"`
		Sign   string `json:"sign"`
	} `json:"url_params"`
}

type postRatingResData struct {
	Success bool `json:"ok"`
}

func handlePostRating(ctx *fasthttp.RequestCtx, dbpool *pgxpool.Pool) (response *responseData) {
	reqData := new(postRatingReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 1234,
				ErrorMsg:  "Error occured while unmarshall your json",
			},
		}
	}

	u, err := url.Parse("?" + reqData.URLParams.Params)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 1234,
				ErrorMsg:  "Malformed `url_params`",
			},
		}
	}

	vkTs, err := strconv.ParseInt(u.Query().Get("vk_ts"), 10, 64)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "Unable to parse vk_user_id form url params",
			},
		}
	}

	tn := time.Now()

	if tn.Sub(time.Unix(vkTs, 0)) > time.Hour*2 {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "Your vk_ts is expired",
			},
		}
	}

	requesterVKUserID64, err := strconv.ParseUint(u.Query().Get("vk_user_id"), 10, 32)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "Unable to parse vk_user_id form url params",
			},
		}
	}

	requesterVKUserID := uint32(requesterVKUserID64)

	if requesterVKUserID == reqData.VKUserID {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "You can't rate yourself",
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
				ErrorCode: 666,
				ErrorMsg:  "Sign/urlparams is not correct",
			},
		}
	}

	if reqData.Rate > 5 || reqData.Rate == 0 {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "`rate` can only be 5, 3, 2 or 1",
			},
		}
	}

	dbtx, err := dbpool.BeginTx(ctx, pgx.TxOptions{
		IsoLevel:       pgx.Serializable,
		AccessMode:     pgx.ReadWrite,
		DeferrableMode: pgx.NotDeferrable,
	})

	var deferredCommit = true
	defer func() {
		if !deferredCommit {
			return
		}

		err := dbtx.Commit(context.Background())
		if err != nil {
			zap.L().Error(err.Error())
		}
	}()

	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	var (
		remainingUserRates   int16
		userRatesRestoreTime time.Time
	)

	err = dbtx.QueryRow(ctx, "SELECT remaining_user_rates, user_rates_restore_time FROM users WHERE vk_user_id = $1;", requesterVKUserID).Scan(&remainingUserRates, &userRatesRestoreTime)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	if userRatesRestoreTime.Sub(tn) <= 0 {
		remainingUserRates = 9

		_, err = dbtx.Exec(ctx, "INSERT INTO users (vk_user_id, remaining_user_rates, user_rates_restore_time) VALUES ($1, 9, NOW() + INTERVAL '1 DAY') ON CONFLICT (vk_user_id) DO UPDATE SET remaining_user_rates = EXCLUDED.remaining_user_rates, user_rates_restore_time = EXCLUDED.user_rates_restore_time;", requesterVKUserID)
		if err != nil {
			zap.L().Error(err.Error())
			return &responseData{
				Err: &responseErrData{
					ErrorCode: 777,
					ErrorMsg:  "Internal error",
				},
			}
		}
	}

	if remainingUserRates <= 0 {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 98765,
				ErrorMsg:  "You can rate only 9 times per 24 hours",
			},
		}
	}

	var (
		remainingUserTargetRates   int16
		userTargetRatesRestoreTime time.Time
	)

	err = dbtx.QueryRow(ctx, "SELECT remaining_user_target_rates, user_target_rates_restore_time FROM user_rates_times WHERE (vk_user_id = $1 AND target_vk_user_id = $2);", requesterVKUserID, reqData.VKUserID).Scan(&remainingUserTargetRates, &userTargetRatesRestoreTime)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	if userTargetRatesRestoreTime.Sub(tn) <= 0 {
		remainingUserTargetRates = 2

		_, err = dbtx.Exec(ctx, "INSERT INTO user_rates_times (vk_user_id, target_vk_user_id, remaining_user_target_rates, user_target_rates_restore_time) VALUES ($1, $2, 2, NOW() + INTERVAL '1 DAY') ON CONFLICT (vk_user_id, target_vk_user_id) DO UPDATE SET remaining_user_target_rates = EXCLUDED.remaining_user_target_rates, user_target_rates_restore_time = EXCLUDED.user_target_rates_restore_time;", requesterVKUserID, reqData.VKUserID)
		if err != nil {
			zap.L().Error(err.Error())
			return &responseData{
				Err: &responseErrData{
					ErrorCode: 777,
					ErrorMsg:  "Internal error",
				},
			}
		}
	}

	if remainingUserTargetRates <= 0 {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 4321,
				ErrorMsg:  "You can rate one user only 2 times per 24 hours",
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

	_, err = dbtx.Exec(ctx, "INSERT INTO users (vk_user_id, "+ratingCountColumnName+") VALUES ($1, 1) ON CONFLICT (vk_user_id) DO UPDATE SET "+ratingCountColumnName+" = (SELECT "+ratingCountColumnName+" FROM users WHERE vk_user_id = $1) + 1;", reqData.VKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	_, err = dbtx.Exec(ctx, "INSERT INTO users (vk_user_id, remaining_user_rates) VALUES ($1, 8) ON CONFLICT (vk_user_id) DO UPDATE SET remaining_user_rates = (SELECT remaining_user_rates FROM users WHERE vk_user_id = $1) - 1;", requesterVKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	_, err = dbtx.Exec(ctx, "INSERT INTO user_rates_times (vk_user_id, target_vk_user_id, remaining_user_target_rates) VALUES ($1, $2, 1) ON CONFLICT (vk_user_id, target_vk_user_id) DO UPDATE SET remaining_user_target_rates = (SELECT remaining_user_target_rates FROM user_rates_times WHERE (vk_user_id = $1 AND target_vk_user_id = $2)) - 1;", requesterVKUserID, reqData.VKUserID)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	deferredCommit = false

	err = dbtx.Commit(ctx)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Internal error",
			},
		}
	}

	return &responseData{
		Response: &postRatingResData{
			Success: true,
		},
	}
}

type vkUsersGetReqData struct {
	UserIDs   string `json:"user_ids"`
	Lang      string `json:"lang"`
	URLParams struct {
		Params string `json:"params"`
		Sign   string `json:"sign"`
	} `json:"url_params"`
}

func handleVKUsersGet(ctx *fasthttp.RequestCtx) (response *responseData) {
	reqData := new(vkUsersGetReqData)
	err := jsoniter.Unmarshal(ctx.Request.Body(), reqData)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 1234,
				ErrorMsg:  "Error occured while unmarshall your json",
			},
		}
	}

	u, err := url.Parse("?" + reqData.URLParams.Params)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 1234,
				ErrorMsg:  "Malformed `url_params`",
			},
		}
	}

	vkTs, err := strconv.ParseInt(u.Query().Get("vk_ts"), 10, 64)
	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "Unable to parse vk_user_id form url params",
			},
		}
	}

	tn := time.Now()

	if tn.Sub(time.Unix(vkTs, 0)) > time.Hour*24 {
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 666,
				ErrorMsg:  "Your vk_ts is expired, it was 24 hours ago",
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
				ErrorCode: 666,
				ErrorMsg:  "Sign/urlparams is not correct",
			},
		}
	}

	_, body, err := fasthttpClient.GetTimeout(nil, "https://api.vk.com/method/users.get?v=5.126&access_token="+vkServiceKey+"&lang="+url.QueryEscape(reqData.Lang)+"&user_ids="+url.QueryEscape(reqData.UserIDs)+"&fields=photo_200,screen_name", time.Second*5)

	if err != nil {
		zap.L().Error(err.Error())
		return &responseData{
			Err: &responseErrData{
				ErrorCode: 777,
				ErrorMsg:  "Error occured while doing request to VK api",
			},
		}
	}

	ctx.SetContentType("application/json; charset=utf8")
	ctx.SetBody(body)

	return nil
}
