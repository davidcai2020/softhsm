package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type ServerCfg struct {
	Host string `yaml:"host"`
	Port string `yaml:"port"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

var (
	envSSMConfigPath = "SSM_CONFIG_PATH"
)

func GetConf() (*ServerCfg, string, error) {
	// get ssm config path
	cfgPath := os.Getenv(envSSMConfigPath)
	if cfgPath == "" {
		es := fmt.Sprintf("environment variable %s is not set.", envSSMConfigPath)
		return nil, "", errors.New(es)
	}
	filename := cfgPath + "/config.yaml"
	log.Println("filename: " + filename)

	// load config file
	yamlFile, err := ioutil.ReadFile(filename)
	if err != nil {
		es := fmt.Sprintf("failed to load %s: %v", filename, err)
		return nil, "", errors.New(es)
	}

	// fill svfCfg
	svrCfg := ServerCfg{}
	err = yaml.Unmarshal(yamlFile, &svrCfg)
	if err != nil {
		es := fmt.Sprintf("Yaml unmarshal failed: %v.", err)
		return nil, "", errors.New(es)
	}
	log.Printf("svrCfg = %+v\n", svrCfg)

	return &svrCfg, cfgPath, nil
}
