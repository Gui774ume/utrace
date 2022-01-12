/*
Copyright © 2021 GUILLAUME FOURNIER

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utrace

import (
	"math/rand"
	"strings"
	"time"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func sanitizeFuncName(name string) string {
	escapedName := strings.ReplaceAll(name, "*", `\*`)
	escapedName = strings.ReplaceAll(escapedName, "(", `\(`)
	escapedName = strings.ReplaceAll(escapedName, ")", `\)`)
	escapedName = strings.ReplaceAll(escapedName, "[", `\[`)
	escapedName = strings.ReplaceAll(escapedName, "]", `\]`)
	return escapedName
}

var (
	letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
)

func randomStringFromSliceWithLen(runes []rune, n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(runes))]
	}
	return string(b)
}

// RandomStringWithLen returns a random string of specified length containing
// upper- and lowercase runes.
func RandomStringWithLen(n int) string {
	return randomStringFromSliceWithLen(letterRunes, n)
}
