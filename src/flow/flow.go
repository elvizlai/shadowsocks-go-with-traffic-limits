package flow

import (
	"encoding/json"
	"io/ioutil"
	"os"
	//"time"
)

type Info struct {
	CreateTime string              `json:"create_time"`
	Usage      map[string][]string `json:"flow_info"`
}

func ParseConfig(path string) (config *Info, err error) {
	file, err := os.Open(path) // For read access.
	if err != nil {
		return
	}
	defer file.Close()

	data, err := ioutil.ReadAll(file)
	if err != nil {
		return
	}

	config = &Info{}
	if err = json.Unmarshal(data, config); err != nil {
		return nil, err
	}
	//readTimeout = time.Duration(config.Timeout) * time.Second
	return
}

func SaveConfig(path string, info *Info) {
	file, err := os.Create(path)
	if err != nil {
		return
	}
	defer file.Close()

	body, _ := json.Marshal(info)

	file.Write(body)
}
