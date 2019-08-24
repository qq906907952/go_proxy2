package util

import (
	"fmt"
	"log"
	"os"
	"time"
)

var Log_verbose = log.Logger{}

func init() {
	Log_verbose.SetOutput(os.Stdout)
}

func Print_log(id uint16, log string, v ...interface{}) {

	file, err := os.OpenFile("go_proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("can not open log file:" + err.Error())
		return
	}
	fmt.Fprintf(file, time.Now().Format(time.RFC3339)+"	"+fmt.Sprintf("id:%d", id)+"	"+log+"\r\n", v...)
	file.Close()
}

func Print_log_without_id(log string, v ...interface{}) {

	file, err := os.OpenFile("go_proxy.log", os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
	if err != nil {
		fmt.Println("can not open log file:" + err.Error())
		return
	}
	fmt.Fprintf(file, time.Now().Format(time.RFC3339)+"	"+log+"\r\n", v...)
	file.Close()
}

func Print_verbose(msg string, v ...interface{}) {
	Log_verbose.Printf(time.Now().Format(time.RFC3339)+"	"+msg, v...)
}
