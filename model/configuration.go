package model

import (
	"gopkg.in/yaml.v2"
	"log"
	"os"
)

type NodeList struct {
	Nodes Node `yaml:"node"`
}
type Properties struct {
	Nodes            []NodeList `yaml:"nodes"`
	NetworkInterface string     `yaml:"network_interface"`
}

// panics on error
func (properties *Properties) ReadPropertiesFile(path string) {
	yamlFile, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Reading yaml file from path %s raised error #%v", path, err)
		panic(err)
	}
	err = yaml.Unmarshal(yamlFile, properties)
	if err != nil {
		log.Printf("Unmarshall #%v", err)
		panic(err)
	}
}
