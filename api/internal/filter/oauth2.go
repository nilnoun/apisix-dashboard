package filter

import (
	"fmt"
	"github.com/google/uuid"
	"io"
	"net/http"

	"github.com/apisix/manager-api/internal/conf"
	"github.com/apisix/manager-api/internal/log"
	"github.com/apisix/manager-api/internal/utils/jwt"
	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

const (
	Oauth2Name           = "oauth2"
	Oauth2StateCookieKey = "oauth2_state"
	Oauth2TokenCookieKey = "oauth2_token"

	Oauth2LoginPath    = "/apisix/admin/oauth2/login"
	Oauth2CallbackPath = "/apisix/admin/oauth2/callback"
	Oauth2LogoutPath   = "/apisix/admin/oauth2/logout"
)

func Oauth2() gin.HandlerFunc {
	auth := new(oath2)
	return func(ctx *gin.Context) {
		switch ctx.Request.URL.Path {
		case Oauth2LoginPath:
			auth.Login(ctx)
		case Oauth2CallbackPath:
			auth.Callback(ctx)
		case Oauth2LogoutPath:
			ctx.AbortWithStatus(http.StatusOK)
		default:
			ctx.Next()
		}
	}
}

type oath2 struct{}

func (o *oath2) Login(ctx *gin.Context) {
	state := uuid.New().String()
	ctx.SetCookie(Oauth2StateCookieKey, state, 300, Oauth2CallbackPath, "", false, true)
	url := conf.Oauth2Config.AuthCodeURL(state)
	ctx.Redirect(302, url)
	ctx.Abort()
	return
}

func (o *oath2) Callback(ctx *gin.Context) {
	authState, _ := ctx.Cookie(Oauth2StateCookieKey)
	ctx.SetCookie(Oauth2StateCookieKey, "", 0, Oauth2CallbackPath, "", false, true)

	if ctx.Query("state") != authState {
		log.Warn("the state does not match")
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	// in exchange for token
	token, err := conf.Oauth2Config.Exchange(ctx, ctx.Query("code"))
	if err != nil {
		log.Warnf("exchange code for token failed: %s", err)
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	// in exchange for user's information
	userinfo, err := o.GetUserInfoByToken(conf.Oauth2UserInfoURL, token.AccessToken)
	if err != nil {
		log.Warnf("get user info by access_token failed: %s", err)
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	if !conf.Oauth2WhitelistSet.Contains(userinfo.UserId) {
		log.Warnf("The user is not on the whitelist, user_id: %s", userinfo.UserId)
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	userToken, err := jwt.GenToken(userinfo, conf.Oauth2ExpireTime, conf.AuthConf.Secret, Oauth2Name)
	if err != nil {
		log.Warnf("gen user's token information failed: %s", err)
		ctx.AbortWithStatus(http.StatusForbidden)
		return
	}

	ctx.SetCookie(Oauth2TokenCookieKey, userToken, 60, "/", "", false, false)
	ctx.Redirect(http.StatusTemporaryRedirect, "/")
	ctx.Abort()
	return

}

func (o *oath2) GetUserInfoByToken(url string, token string) (*jwt.Userinfo, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fail to get user info by token: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	data := &jwt.Userinfo{
		UserId: gjson.GetBytes(body, conf.Oauth2UserinfoField.ID).String(),
		Name:   gjson.GetBytes(body, conf.Oauth2UserinfoField.Name).String(),
		Avatar: gjson.GetBytes(body, conf.Oauth2UserinfoField.Avatar).String(),
	}

	return data, nil
}
