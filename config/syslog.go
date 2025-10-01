package config

import (
	"fmt"

	"go.uber.org/zap"
)

func RestartSyslog(c *Config) {
	zap.L().Info("Restart container nfg-syslog")
	err := forceRemoveContainer("nfg-syslog")
	if err != nil {
		zap.L().Warn("Failed to stop container nfg-syslog:", zap.Error(err))
	}

	if err := generateSyslogConfig(c); err != nil {
		zap.L().Error("Failed to generate syslog config", zap.Error(err))
		return
	}
	zap.L().Info("Generated syslog config successfully")

	if err := startContainer("nfg-syslog", c); err != nil {
		zap.L().Error("Failed to start syslog container", zap.String("container", "nfg-syslog"), zap.Error(err))
		return
	}
	zap.L().Info("Syslog container started", zap.String("container", "nfg-syslog"))
}

func HandleSyslogChange(c *Config) {
	if c.SyslogEnabled {
		zap.L().Info("Syslog enabled, generating config and starting container",
			zap.String("aggregatorName", c.AggregatorName),
		)

		// Check if container "nfg-syslog" exists
		if containerExists("nfg-syslog") {
			zap.L().Info("Container nfg-syslog exists, attempting removal")
			err := forceRemoveContainer("nfg-syslog")
			if err != nil {
				zap.L().Warn("Failed to stop/remove container nfg-syslog", zap.Error(err))
			}
			zap.L().Info("Successfully stopped/removed container nfg-syslog")
		} else {
			zap.L().Info("No existing container nfg-syslog found")
		}

		if err := generateSyslogConfig(c); err != nil {
			zap.L().Error("Failed to generate syslog config", zap.Error(err))
			return
		}
		zap.L().Info("Generated syslog config successfully")

		if err := startContainer("nfg-syslog", c); err != nil {
			zap.L().Error("Failed to start syslog container", zap.String("container", "nfg-syslog"), zap.Error(err))
			return
		}
		zap.L().Info("Syslog container started", zap.String("container", "nfg-syslog"))

	} else {
		zap.L().Info("Syslog disabled, stopping container and cleaning config",
			zap.String("container", "nfg-syslog"),
		)

		if err := stopContainer("nfg-syslog"); err != nil {
			zap.L().Error("Failed to stop syslog container", zap.String("container", "nfg-syslog"), zap.Error(err))
		} else {
			zap.L().Info("Stopped syslog container", zap.String("container", "nfg-syslog"))
		}
	}
}

func generateSyslogConfig(c *Config) error {
	zap.L().Info("Generating syslog config",
		zap.String("path", "./syslog/syslog-ng.conf"),
		zap.String("aggregatorName", c.AggregatorName),
	)

	headers := `@version: 4.7
@include "scl.conf"
	`

	source := `source s_local {
	internal();
};

source s_network_firepower {
	syslog(transport("udp") port(514));
};

source s_network_ise {
	syslog(transport("udp") port(1025));
};
	`

	destination := fmt.Sprintf(`destination d_http_ise {
	http(
		url("%s/ise")
		method("POST")
		headers("X-AUTH_KEY: %s")
		headers("X-AGGREGATOR_NAME: %s")
		body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM: $MSG")
	);
};

destination d_http_firepower {
	http(
		url("%s/firepower")
		method("POST")
		headers("X-AUTH_KEY: %s")
		headers("X-AGGREGATOR_NAME: %s")
		body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM: $MSG")
	);
};
	`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName,
		c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)

	log := `log {
	source(s_network_ise);
	destination(d_http_ise);
};

log {
	source(s_network_firepower);
	destination(d_http_firepower);
};
	`

	fullConf := headers + "\n\n" + source + "\n\n" + destination + "\n\n" + log
	c.SyslogConfig = fullConf

	return nil
}
