// Copyright 2020 the Drone Authors. All rights reserved.
// Use of this source code is governed by the Blue Oak Model License
// that can be found in the LICENSE file.

package main

import (
	"context"

	"github.com/drone/drone-veracode/plugin"
	"github.com/kelseyhightower/envconfig"
	"github.com/sirupsen/logrus"
)

func main() {
	logrus.SetFormatter(new(formatter))

	var args plugin.Args
	if err := envconfig.Process("", &args); err != nil {
		logrus.Fatalf("\nFailed to process arguments: %s", err)
	}

	switch args.Level {
	case "debug":
		logrus.SetFormatter(textFormatter)
		logrus.SetLevel(logrus.DebugLevel)
	case "trace":
		logrus.SetFormatter(textFormatter)
		logrus.SetLevel(logrus.TraceLevel)
	}

	logrus.Info("Starting Veracode plugin execution\n")

	// Execute the plugin logic
	if err := plugin.Exec(context.Background(), args); err != nil {
		logrus.Fatalf("\nPlugin execution failed: %v", err)
	}

	logrus.Info("\nPlugin execution completed successfully")
}

// default formatter that writes logs without including timestamp
// or level information.
type formatter struct{}

func (*formatter) Format(entry *logrus.Entry) ([]byte, error) {
	return []byte(entry.Message), nil
}

// text formatter that writes logs with level information
var textFormatter = &logrus.TextFormatter{
	DisableTimestamp: true,
}
