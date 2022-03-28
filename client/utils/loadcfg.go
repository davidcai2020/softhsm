package utils

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"gopkg.in/yaml.v2"
)

type ClientCfg struct {
	Host   string `yaml:"host"`
	Port   string `yaml:"port"`
	Cert   string `yaml:"cert"`
	Key    string `yaml:"key"`
	CACert string `yaml:"cacert"`
}

var (
	envClientConfigPath = "CLIENT_CONFIG_PATH"
)

func GetConf() (*ClientCfg, string, error) {
	// get ccm config path
	cfgPath := os.Getenv(envClientConfigPath)
	if cfgPath == "" {
		es := fmt.Sprintf("environment variable %s is not set.", envClientConfigPath)
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

	// fill cliCfg
	cliCfg := ClientCfg{}
	err = yaml.Unmarshal(yamlFile, &cliCfg)
	if err != nil {
		es := fmt.Sprintf("Yaml unmarshal failed: %v.", err)
		return nil, "", errors.New(es)
	}
	log.Printf("cliCfg = %+v\n", cliCfg)

	return &cliCfg, cfgPath, nil
}
