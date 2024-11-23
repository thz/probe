// Copyright 2020 Tobias Hintze
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package probe

import "errors"

var (
	ErrProxyProtocolDisabled = errors.New("proxy protocol disabled")
	ErrInvalidArgument       = errors.New("invalid argument")
	ErrUnexpectedResponse    = errors.New("unexpected response")
	ErrProtocolViolation     = errors.New("protocol violation")
	ErrResolve               = errors.New("name resolution error")
	ErrProxyProtocol         = errors.New("proxy protocol error")
	ErrTCP                   = errors.New("TCP error")
)
