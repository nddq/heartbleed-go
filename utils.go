package main

import (
	"fmt"
	"strconv"
)

func convertToInt(arr []byte) (int64, error) {
	hex := ""
	for _, v := range arr {
		strform := fmt.Sprintf("%x", v)
		if len(strform) < 2 {
			strform = "0" + strform
		}
		hex = hex + strform
	}
	i, err := strconv.ParseInt(hex, 16, 32)
	if err != nil {
		return 0, err
	}
	return i, err
}
