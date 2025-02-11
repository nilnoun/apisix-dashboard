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
	"net/http"
	"strings"

	"github.com/apisix/manager-api/internal/utils/jwt"
	"github.com/gin-gonic/gin"

	"github.com/apisix/manager-api/internal/conf"
	"github.com/apisix/manager-api/internal/log"
)

func Authentication() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/apisix/admin/user/login" ||
			c.Request.URL.Path == "/apisix/admin/tool/version" ||
			!strings.HasPrefix(c.Request.URL.Path, "/apisix") {
			c.Next()
			return
		}

		errResp := gin.H{
			"code":    010013,
			"message": "request unauthorized",
		}

		tokenStr := c.GetHeader("Authorization")

		userinfo, err := jwt.ParseToken(tokenStr, conf.AuthConf.Secret)
		if err != nil {
			log.Warnf("token validate failed: %s", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp)
			return
		}

		if err = userinfo.StandardClaims.Valid(); err != nil {
			log.Warnf("token claims validate failed: %s", err)
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp)
			return
		}

		if userinfo.UserId == "" {
			log.Warn("token claims subject empty")
			c.AbortWithStatusJSON(http.StatusUnauthorized, errResp)
			return
		}

		switch userinfo.StandardClaims.Issuer {
		case "password":
			if _, ok := conf.UserList[userinfo.UserId]; !ok {
				log.Warnf("user not exists by token claims subject %s", userinfo.UserId)
				c.AbortWithStatusJSON(http.StatusUnauthorized, errResp)
				return
			}
		}

		c.Set("userinfo", userinfo.Userinfo)
		c.Next()
	}
}
