/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package filter

import (
	"github.com/google/uuid"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/apisix/manager-api/internal/conf"
	"github.com/apisix/manager-api/internal/log"
	"github.com/apisix/manager-api/internal/utils/jwt"
)

const (
	OIDCName           = "oidc"
	OIDCStateCookieKey = "oidc_state"
	OIDCTokenCookieKey = "oidc_token"

	OIDCLoginPath    = "/apisix/admin/oidc/login"
	OIDCCallbackPath = "/apisix/admin/oidc/callback"
	OIDCLogoutPath   = "/apisix/admin/oidc/logout"
)

type Token struct {
	AccessToken string
}

func (token *Token) Token() (*oauth2.Token, error) {
	oauth2Token := &oauth2.Token{AccessToken: token.AccessToken}
	return oauth2Token, nil
}

func Oidc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == OIDCLoginPath {
			state := uuid.New().String()
			c.SetCookie(OIDCStateCookieKey, state, 300, OIDCCallbackPath, "", false, true)

			url := conf.OidcConfig.AuthCodeURL(state)
			c.Redirect(302, url)
			c.Abort()
			return
		}

		if c.Request.URL.Path == OIDCCallbackPath {
			authState, _ := c.Cookie(OIDCStateCookieKey)
			c.SetCookie(OIDCStateCookieKey, "", -1, OIDCCallbackPath, "", false, true)

			state := c.Query("state")
			if state != authState {
				log.Warn("the state does not match")
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			// in exchange for token
			oauth2Token, err := conf.OidcConfig.Exchange(c, c.Query("code"))
			if err != nil {
				log.Warnf("exchange code for token failed: %s", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			// in exchange for user's information
			token := &Token{oauth2Token.AccessToken}
			providerConfig := oidc.ProviderConfig{UserInfoURL: conf.OidcUserInfoURL}
			userInfo, err := providerConfig.NewProvider(c).UserInfo(c, token)
			if err != nil {
				log.Warnf("exchange access_token for user's information failed: %s", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			// set the cookie
			info := &jwt.Userinfo{
				Name:   userInfo.Email,
				UserId: userInfo.Email,
			}

			var claims map[string]any
			if err = userInfo.Claims(&claims); err != nil {
				log.Warnf("provider claims failed: %s", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}
			info.Avatar, _ = claims["picture"].(string)
			if name, ok := claims["name"].(string); ok {
				info.Name = name
			}

			userToken, err := jwt.GenToken(info, conf.AuthConf.ExpireTime, conf.AuthConf.Secret, OIDCName)
			if err != nil {
				log.Warnf("gen user's token information failed: %s", err)
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.SetCookie(OIDCTokenCookieKey, userToken, 60, "/", "", false, false)
			c.Redirect(http.StatusTemporaryRedirect, "/")
			c.Abort()
			return
		}

		if c.Request.URL.Path == OIDCLogoutPath {
			c.AbortWithStatus(http.StatusOK)
			return
		}

		c.Next()
	}
}
