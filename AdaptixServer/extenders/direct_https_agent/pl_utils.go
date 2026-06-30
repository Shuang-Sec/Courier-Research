// 文件作用：服务端通用工具函数：命令编号、RC4 加解密、时间解析、系统版本和大小格式化等。
package main

import (
	"crypto/rc4"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"regexp"
	"strconv"
	"strings"

	adaptix "github.com/Adaptix-Framework/axc2"
)

const (
	COMMAND_CAT            = 24
	COMMAND_COPY           = 12
	COMMAND_CD             = 8
	COMMAND_DOWNLOAD       = 32
	COMMAND_DOWNLOAD_STATE = 35
	COMMAND_HELLO          = 0x9001
	COMMAND_JOBS_KILL      = 47
	COMMAND_LS             = 14
	COMMAND_MV             = 18
	COMMAND_MKDIR          = 27
	COMMAND_PS_RUN         = 43
	COMMAND_PWD            = 4
	COMMAND_RM             = 17
	COMMAND_TERMINATE      = 10
	COMMAND_UPLOAD         = 33

	COMMAND_JOB        = 0x8437
	COMMAND_SAVEMEMORY = 0x2321
	COMMAND_ERROR      = 0x1111ffff
)

const (
	DOWNLOAD_START    = 0x1
	DOWNLOAD_CONTINUE = 0x2
	DOWNLOAD_FINISH   = 0x3
)

const (
	JOB_STATE_RUNNING  = 0x1
	JOB_STATE_FINISHED = 0x2
	JOB_STATE_KILLED   = 0x3
)

// CreateTaskCommandSaveMemory 给指定 agent 创建“保存内存分片”的后台任务。
func CreateTaskCommandSaveMemory(ts Teamserver, agentId string, buffer []byte) int {
	chunkSize := 0x100000 // 1Mb
	memoryId := int(rand.Uint32())

	bufferSize := len(buffer)
	taskData := adaptix.TaskData{
		Type:    adaptix.TASK_TYPE_TASK,
		AgentId: agentId,
		Sync:    false,
	}

	for start := 0; start < bufferSize; start += chunkSize {
		fin := start + chunkSize
		if fin > bufferSize {
			fin = bufferSize
		}

		array := []interface{}{COMMAND_SAVEMEMORY, memoryId, bufferSize, fin - start, buffer[start:fin]}
		taskData.Data, _ = PackArray(array)
		taskData.TaskId = fmt.Sprintf("%08x", rand.Uint32())

		ts.TsTaskCreate(agentId, "", "", taskData)
	}
	return memoryId
}

// GetOsVersion 根据 Windows 版本号、build 号和架构拼出界面上显示的系统名称。
func GetOsVersion(majorVersion uint8, minorVersion uint8, buildNumber uint, isServer bool, systemArch string) (int, string) {
	var (
		desc string
		os   = adaptix.OS_UNKNOWN
	)

	osVersion := "unknown"
	if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 26100 {
		osVersion = "Win 2025 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 19045 {
		osVersion = "Win 2022 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && isServer && buildNumber >= 17763 {
		osVersion = "Win 2019 Serv"
	} else if majorVersion == 10 && minorVersion == 0 && !isServer && buildNumber >= 22000 {
		osVersion = "Win 11"
	} else if majorVersion == 10 && minorVersion == 0 && isServer {
		osVersion = "Win 2016 Serv"
	} else if majorVersion == 10 && minorVersion == 0 {
		osVersion = "Win 10"
	} else if majorVersion == 6 && minorVersion == 3 && isServer {
		osVersion = "Win Serv 2012 R2"
	} else if majorVersion == 6 && minorVersion == 3 {
		osVersion = "Win 8.1"
	} else if majorVersion == 6 && minorVersion == 2 && isServer {
		osVersion = "Win Serv 2012"
	} else if majorVersion == 6 && minorVersion == 2 {
		osVersion = "Win 8"
	} else if majorVersion == 6 && minorVersion == 1 && isServer {
		osVersion = "Win Serv 2008 R2"
	} else if majorVersion == 6 && minorVersion == 1 {
		osVersion = "Win 7"
	}

	desc = osVersion + " " + systemArch
	if strings.Contains(osVersion, "Win") {
		os = adaptix.OS_WINDOWS
	}
	return os, desc
}

// int32ToIPv4 把 32 位整数形式的内网 IP 转成常见的点分十进制字符串。
func int32ToIPv4(ip uint) string {
	b := []byte{
		byte(ip),
		byte(ip >> 8),
		byte(ip >> 16),
		byte(ip >> 24),
	}
	return net.IP(b).String()
}

// SizeBytesToFormat 把字节数转换成更容易看的 B/KB/MB/GB 文本。
func SizeBytesToFormat(bytes int64) string {
	const (
		KB = 1024.0
		MB = KB * 1024
		GB = MB * 1024
	)

	size := float64(bytes)
	if size >= GB {
		return fmt.Sprintf("%.2f Gb", size/GB)
	} else if size >= MB {
		return fmt.Sprintf("%.2f Mb", size/MB)
	}
	return fmt.Sprintf("%.2f Kb", size/KB)
}

// RC4Crypt 用 RC4 对数据加密或解密；RC4 是对称算法，同一个函数可双向使用。
func RC4Crypt(data []byte, key []byte) ([]byte, error) {
	rc4crypt, errcrypt := rc4.NewCipher(key)
	if errcrypt != nil {
		return nil, errors.New("rc4 crypt error")
	}
	cryptData := make([]byte, len(data))
	rc4crypt.XORKeyStream(cryptData, data)
	return cryptData, nil
}

// parseDurationToSeconds 把 4s、2m、1h2m3s 这类 sleep 文本转换成秒。
func parseDurationToSeconds(input string) (int, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return 0, errors.New("sleep must be set")
	}
	if seconds, err := strconv.Atoi(input); err == nil {
		return seconds, nil
	}

	re := regexp.MustCompile(`(\d+)(h|m|s)`)
	matches := re.FindAllStringSubmatch(input, -1)
	if len(matches) == 0 {
		return 0, errors.New("sleep must be in '%h%m%s' format or number of seconds")
	}

	totalSeconds := 0
	consumed := ""
	for _, match := range matches {
		consumed += match[0]
		value, err := strconv.Atoi(match[1])
		if err != nil {
			return 0, err
		}
		switch match[2] {
		case "h":
			totalSeconds += value * 3600
		case "m":
			totalSeconds += value * 60
		case "s":
			totalSeconds += value
		}
	}
	if consumed != input {
		return 0, errors.New("sleep must be in '%h%m%s' format or number of seconds")
	}
	return totalSeconds, nil
}

// parseStringToWorkingTime 把 HH:mm-HH:mm 的工作时间段转换成 agent 使用的紧凑整数。
func parseStringToWorkingTime(WorkingTime string) (int, error) {
	IntWorkingTime := 0
	if WorkingTime != "" {
		match, err := regexp.MatchString("^[012]?[0-9]:[0-6][0-9]-[012]?[0-9]:[0-6][0-9]$", WorkingTime)
		if err != nil || match == false {
			return IntWorkingTime, errors.New("Failed to parse working time: Invalid format")
		}

		startAndEnd := strings.Split(WorkingTime, "-")
		startHourandMinutes := strings.Split(startAndEnd[0], ":")
		endHourandMinutes := strings.Split(startAndEnd[1], ":")

		startHour, _ := strconv.Atoi(startHourandMinutes[0])
		startMin, _ := strconv.Atoi(startHourandMinutes[1])
		endHour, _ := strconv.Atoi(endHourandMinutes[0])
		endMin, _ := strconv.Atoi(endHourandMinutes[1])

		if startHour < 0 || startHour > 24 || endHour < 0 || endHour > 24 || startMin < 0 || startMin > 60 || endMin < 0 || endMin > 60 {
			return IntWorkingTime, errors.New("Failed to parse working time: Incorrectly defined time")
		}

		if endHour < startHour || (startHour == endHour && endMin <= startMin) {
			return IntWorkingTime, errors.New("Failed to parse working time: The end hour cannot be earlier than the start hour")
		}

		IntWorkingTime |= startHour << 24
		IntWorkingTime |= startMin << 16
		IntWorkingTime |= endHour << 8
		IntWorkingTime |= endMin << 0
	}

	return IntWorkingTime, nil
}
