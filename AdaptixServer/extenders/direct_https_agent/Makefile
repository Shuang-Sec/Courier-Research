# 文件作用：direct_https_agent 插件构建脚本：编译 Go 插件，并生成 Windows agent 需要的对象文件。
# all 目标：清理旧 dist，编译 Go 插件，并编译 Windows agent 对象文件。
all: clean
	@ echo "    * Building agent_direct_https plugin"
	@ mkdir dist
	@ cp config.yaml ax_config.axs ./dist/
	@ GOEXPERIMENT=jsonv2,greenteagc go build -buildmode=plugin -ldflags="-s -w" -o ./dist/agent_direct_https.so pl_main.go pl_packer.go pl_utils.go
	@ echo "      done..."

	@ echo "    * Building Direct HTTPS agent objects"
	@ (cd src_beacon && $(MAKE) --no-print-directory)
	@ mv src_beacon/objects_http ./dist/objects_http
	@ echo "      done..."

# clean 目标：删除上一次生成的 dist 目录。
clean:
	@ rm -rf dist
