//
// Copyright 2026 The Sigstore Authors.
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

package cli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/pflag"
)

// EnvPrefix is prepended to a flag's name to form the environment variable
// that can set it.
const EnvPrefix = "REKOR_"

// EnvHelp describes the environment variable support in a command's help text.
const EnvHelp = "Every flag can also be set through an environment variable named " + EnvPrefix + "<FLAG>,\n" +
	"e.g. " + EnvPrefix + "HTTP_PORT for --http-port. Command-line flags take precedence."

// EnvVarName returns the environment variable that can set the named flag:
// the flag name uppercased, with dashes replaced by underscores and prefixed
// with EnvPrefix. For example, --aws-mysql-dsn can be set with REKOR_AWS_MYSQL_DSN.
func EnvVarName(flagName string) string {
	return EnvPrefix + strings.ToUpper(strings.ReplaceAll(flagName, "-", "_"))
}

// SetFlagsFromEnv sets every flag that was not given on the command line from
// its environment variable (see EnvVarName), if that variable is set and not
// empty. Flags given on the command line take precedence over the environment.
//
// Values are parsed the same way as on the command line, so lists are
// comma-separated and malformed values are reported as errors instead of
// silently falling back to a zero value.
//
// It must be called after the command line has been parsed, i.e. from a
// command's Run function.
func SetFlagsFromEnv(flags *pflag.FlagSet) error {
	var errs []error
	flags.VisitAll(func(f *pflag.Flag) {
		if f.Changed {
			return
		}
		name := EnvVarName(f.Name)
		val, ok := os.LookupEnv(name)
		if !ok || val == "" {
			return
		}
		if err := flags.Set(f.Name, val); err != nil {
			errs = append(errs, fmt.Errorf("environment variable %s: %w", name, err))
		}
	})
	return errors.Join(errs...)
}
