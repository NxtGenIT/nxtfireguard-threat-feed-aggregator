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
	shouldRun := c.SyslogEnabled && AnyEnabled(c.SyslogServices)

	if shouldRun {
		zap.L().Info("Syslog enabled with active services, generating config and starting container",
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

	// Sources
	source := `
source s_local {
	internal();
};
	`

	if c.SyslogServices.SyslogCiscoFtdEnabled {
		source += `
source s_network_firepower {
	syslog(transport("udp") port(514));
};
		`
	}

	if c.SyslogServices.SyslogCiscoIseEnabled {
		source += `
source s_network_ise {
	syslog(transport("udp") port(1025));
};
		`
	}

	if c.SyslogServices.SyslogOpnsenseEnabled {
		source += `
source s_network_opnsense {
	syslog(transport("udp") port(1026));
};
		`
	}

	if c.SyslogServices.SyslogSuricataEnabled {
		source += `
source s_network_suricata {
    internal();
    syslog(transport("udp") port(1027));
};
		`
	}

	// Destinations
	var destination string

	if c.SyslogServices.SyslogCiscoFtdEnabled {
		destination += fmt.Sprintf(`
destination d_http_firepower {
	http(
		url("%s/firepower")
		method("POST")
		msg_data_in_header(no)
		headers("X-AUTH_KEY: %s", "X-AGGREGATOR_NAME: %s")
		body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM: $MSG")
	);
};
		`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)
	}

	if c.SyslogServices.SyslogCiscoIseEnabled {
		destination += fmt.Sprintf(`
destination d_http_ise {
	http(
		url("%s/ise")
		method("POST")
		msg_data_in_header(no)
		headers("X-AUTH_KEY: %s", "X-AGGREGATOR_NAME: %s")
		body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM: $MSG")
	);
};
		`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)
	}

	if c.SyslogServices.SyslogOpnsenseEnabled {
		destination += fmt.Sprintf(`
destination d_http_opnsense {
        http(
                url("%s/opnsense")
                method("POST")
                msg_data_in_header(no)
                headers("X-AUTH_KEY: %s", "X-AGGREGATOR_NAME: %s")
                body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM: $MSG")
        );
};
		`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)
	}

	if c.SyslogServices.SyslogSuricataEnabled {
		destination += fmt.Sprintf(`
destination d_http_suricata{
        http(
                url("%s/suricata")
                method("POST")
                msg_data_in_header(no)
                headers("X-AUTH_KEY: %s", "X-AGGREGATOR_NAME: %s")
                body("<$PRI>$YEAR-$MONTH-$DAYT$HOUR:$MIN:$SEC.$MSEC $HOST $PROGRAM $MSG")
        );
};
		`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)
	}

	// Log
	var log string

	if c.SyslogServices.SyslogCiscoFtdEnabled {
		log += `
log {
	source(s_network_firepower);
	destination(d_http_firepower);
};
		`
	}

	if c.SyslogServices.SyslogCiscoIseEnabled {
		log += `
log {
	source(s_network_ise);
	destination(d_http_ise);
};
		`
	}

	if c.SyslogServices.SyslogOpnsenseEnabled {
		log += `
log {
    source(s_network_opnsense);
    destination(d_http_opnsense);
};
		`
	}

	if c.SyslogServices.SyslogSuricataEnabled {
		log += `
log {
    source(s_network_suricata);
    destination(d_http_suricata);
};
		`
	}

	fullConf := headers + "\n\n" + source + "\n\n" + destination + "\n\n" + log
	c.SyslogConfig = fullConf

	return nil
}
