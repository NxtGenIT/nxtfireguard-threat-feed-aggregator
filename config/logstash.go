package config

import (
	"fmt"
	"strings"

	"go.uber.org/zap"
)

func HandleLogstashChange(c *Config) {
	if c.LogstashEnabled {
		zap.L().Info("Logstash enabled, generating config and starting container",
			zap.String("aggregatorName", c.AggregatorName),
		)

		if err := generateLogstashConfig(c); err != nil {
			zap.L().Error("Failed to generate logstash config", zap.Error(err))
			return
		}
		zap.L().Info("Generated logstash config successfully")

		if err := startContainer("nfg-logstash", c); err != nil {
			zap.L().Error("Failed to start logstash container", zap.String("container", "nfg-logstash"), zap.Error(err))
			return
		}
		zap.L().Info("logstash container started", zap.String("container", "nfg-logstash"))

	} else {
		zap.L().Info("Logstash disabled, stopping container and cleaning config",
			zap.String("container", "nfg-logstash"),
		)

		if err := stopContainer("nfg-logstash"); err != nil {
			zap.L().Error("Failed to stop logstash container", zap.String("container", "nfg-logstash"), zap.Error(err))
		} else {
			zap.L().Info("Stopped logstash container", zap.String("container", "nfg-logstash"))
		}
	}
}

func generateLogstashConfig(c *Config) error {
	zap.L().Info("Generating logstash config",
		zap.String("path", "./logstash/logstash.conf"),
		zap.String("aggregatorName", c.AggregatorName),
	)

	inputBlocks := []string{}

	for _, target := range c.ElasticsearchTargets {
		url := target.URL
		user := target.User
		pass := target.Password

		if url == "" || user == "" {
			continue
		}

		block := fmt.Sprintf(`input {
	elasticsearch {
		hosts => "%s"
		user => "%s"
		password => "%s"
		index => "logstash-*"
		query => '{ "query": { "range": { "@timestamp": { "gt": "now-2s" } } } }'
		schedule => "*/2 * * * * *"
		docinfo => true
	}
}`, url, user, pass)

		inputBlocks = append(inputBlocks, block)
	}

	if len(inputBlocks) == 0 {
		return fmt.Errorf("no valid ELK targets found...")
	}

	outputBlock := fmt.Sprintf(`
output {
	http {
		url => "%s/t-pot"
		http_method => "post"
		format => "json"
		headers => {
			"X-AUTH_KEY" => "%s"
			"X-AGGREGATOR_NAME" => "%s"
		}
	}
}`, c.NfgThreatCollectorUrl, c.AuthSecret, c.AggregatorName)

	fullConf := strings.Join(inputBlocks, "\n\n") + "\n\n" + outputBlock
	c.LogstashConfig = fullConf

	return nil
}
