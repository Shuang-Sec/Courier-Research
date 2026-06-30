/// 文件作用：Adaptix Client 侧 UI/命令配置：定义 direct_https 的可见命令和生成 payload 时的表单。
/// 恢复后的学习版最小功能面：hello、cmd/powershell、文件 CRUD、upload/download。
/// 非目标功能（jobs kill、terminate、disks、download pause/resume/cancel 等）继续不暴露，方便单变量测试。

let AGENT_NAME = "direct_https";

let file_browser_action = menu.create_action("File Browser", function(value) {
    value.forEach(v => ax.open_browser_files(v));
});
menu.add_session_browser(file_browser_action, [AGENT_NAME]);

let download_action = menu.create_action("Download", function(files_list) {
    files_list.forEach((file) => {
        if(file.type == "file") {
            ax.execute_command(file.agent_id, "download " + file.path + file.name);
        }
    });
});
let remove_action = menu.create_action("Remove", function(files_list) {
    files_list.forEach(file => ax.execute_command(file.agent_id, "rm " + file.path + file.name));
});
menu.add_filebrowser(download_action, [AGENT_NAME]);
menu.add_filebrowser(remove_action, [AGENT_NAME]);

var event_files_action = function(id, path) {
    ax.execute_browser(id, "ls " + path);
}
event.on_filebrowser_list(event_files_action, [AGENT_NAME]);

var event_upload_action = function(id, path, filepath) {
    let filename = ax.file_basename(filepath);
    ax.execute_browser(id, "upload " + filepath + " " + path + filename);
}
event.on_filebrowser_upload(event_upload_action, [AGENT_NAME]);

/// RegisterCommands 告诉 Adaptix Client 这个 agent 在界面上有哪些命令按钮/命令行入口。
function RegisterCommands(listenerType)
{
    let cmd_hello = ax.create_command("hello", "Run a minimal hello test inside the agent", "hello", "Task: run hello test");

    let cmd_cmd = ax.create_command("cmd", "Execute a command through cmd.exe", "cmd whoami", "Task: execute cmd.exe command");
    cmd_cmd.addArgString("command_line", true);

    let cmd_powershell = ax.create_command("powershell", "Execute a command through powershell.exe", "powershell Write-Output hello", "Task: execute PowerShell command");
    cmd_powershell.addArgString("command_line", true);

    let cmd_pwd = ax.create_command("pwd", "Print current working directory", "pwd", "Task: print working directory");

    let cmd_cd = ax.create_command("cd", "Change current working directory", "cd C:\\Windows", "Task: change working directory");
    cmd_cd.addArgString("path", true);

    let cmd_ls = ax.create_command("ls", "List directory contents or file details", "ls C:\\Windows", "Task: list files");
    cmd_ls.addArgString("path", "", ".");

    let cmd_cat = ax.create_command("cat", "Read first 2048 bytes of a file", "cat C:\\Temp\\file.txt", "Task: read file");
    cmd_cat.addArgString("path", true);

    let cmd_mkdir = ax.create_command("mkdir", "Create a directory", "mkdir C:\\Temp\\newdir", "Task: make directory");
    cmd_mkdir.addArgString("path", true);

    let cmd_rm = ax.create_command("rm", "Remove a file or empty directory", "rm C:\\Temp\\file.txt", "Task: remove file or directory");
    cmd_rm.addArgString("path", true);

    let cmd_cp = ax.create_command("cp", "Copy file", "cp C:\\a.txt C:\\b.txt", "Task: copy file");
    cmd_cp.addArgString("src", true);
    cmd_cp.addArgString("dst", true);

    let cmd_mv = ax.create_command("mv", "Move or rename file", "mv C:\\a.txt C:\\b.txt", "Task: move file");
    cmd_mv.addArgString("src", true);
    cmd_mv.addArgString("dst", true);

    let cmd_upload = ax.create_command("upload", "Upload a file", "upload /tmp/file.txt C:\\Temp\\file.txt", "Task: upload file");
    cmd_upload.addArgFile("local_file", true);
    cmd_upload.addArgString("remote_path", false);

    let cmd_download = ax.create_command("download", "Download a file", "download C:\\Temp\\file.txt", "Task: download file");
    cmd_download.addArgString("file", true);

    if(listenerType == "BeaconHTTP")
    {
        let commands_http = ax.create_commands_group(AGENT_NAME, [
            cmd_hello,
            cmd_cmd, cmd_powershell,
            cmd_pwd, cmd_cd, cmd_ls,
            cmd_cat, cmd_mkdir, cmd_rm, cmd_cp, cmd_mv,
            cmd_upload, cmd_download
        ]);
        return { commands_windows: commands_http };
    }

    return ax.create_commands_group("none", []);
}

/// GenerateUI 创建生成 payload 时的表单，比如架构、sleep、jitter、代理和 IAT hiding。
function GenerateUI(listeners_type)
{
    let spacer1 = form.create_vspacer();

    let labelArch = form.create_label("Arch:");
    let comboArch = form.create_combo();
    comboArch.addItems(["x64", "x86"]);

    let labelAgentFormat = form.create_label("Format:");
    let comboAgentFormat = form.create_combo();
    comboAgentFormat.addItems(["Exe"]);

    let labelSleep = form.create_label("Sleep (Jitter %):");
    let textSleep = form.create_textline("4s");
    textSleep.setPlaceholder("1h2m5s or 4s");
    let spinJitter = form.create_spin();
    spinJitter.setRange(0, 100);
    spinJitter.setValue(0);

    let checkKilldate = form.create_check("Set 'killdate'");
    let dateKill = form.create_dateline("dd.MM.yyyy");
    let timeKill = form.create_timeline("HH:mm:ss");

    let checkWorkingTime = form.create_check("Set 'workingtime'");
    let timeStart = form.create_timeline("HH:mm");
    let timeFinish = form.create_timeline("HH:mm");


    let checkIatHiding = form.create_check("IAT Hiding (empty import table)");

    let labelProxyType = form.create_label("Type:");
    let comboProxyType = form.create_combo();
    comboProxyType.addItems(["http", "https"]);

    let labelProxyServer = form.create_label("Server:");
    let textProxyServer = form.create_textline("");
    textProxyServer.setPlaceholder("192.168.1.1");
    let spinProxyPort = form.create_spin();
    spinProxyPort.setRange(1, 65535);
    spinProxyPort.setValue(3128);

    let labelProxyUsername = form.create_label("Username:");
    let textProxyUsername = form.create_textline("");
    textProxyUsername.setPlaceholder("(optional)");

    let labelProxyPassword = form.create_label("Password:");
    let textProxyPassword = form.create_textline("");
    textProxyPassword.setPlaceholder("(optional)");

    let layout_group_proxy = form.create_gridlayout();
    layout_group_proxy.addWidget(labelProxyType,     0, 0, 1, 1);
    layout_group_proxy.addWidget(comboProxyType,     0, 1, 1, 2);
    layout_group_proxy.addWidget(labelProxyServer,   1, 0, 1, 1);
    layout_group_proxy.addWidget(textProxyServer,    1, 1, 1, 1);
    layout_group_proxy.addWidget(spinProxyPort,      1, 2, 1, 1);
    layout_group_proxy.addWidget(labelProxyUsername, 2, 0, 1, 1);
    layout_group_proxy.addWidget(textProxyUsername,  2, 1, 1, 2);
    layout_group_proxy.addWidget(labelProxyPassword, 3, 0, 1, 1);
    layout_group_proxy.addWidget(textProxyPassword,  3, 1, 1, 2);

    let panel_group_proxy = form.create_panel();
    panel_group_proxy.setLayout(layout_group_proxy);
    let group_proxy = form.create_groupbox("Use HTTP/HTTPS proxy", true);
    group_proxy.setPanel(panel_group_proxy);
    group_proxy.setChecked(false);

    let labelRotation = form.create_label("Rotation Mode:");
    let comboRotation = form.create_combo();
    comboRotation.addItems(["sequential", "random"]);

    let spacer2 = form.create_vspacer();

    let layout = form.create_gridlayout();
    layout.addWidget(spacer1,          0, 0, 1, 3);
    layout.addWidget(labelArch,        1, 0, 1, 1);
    layout.addWidget(comboArch,        1, 1, 1, 2);
    layout.addWidget(labelAgentFormat, 2, 0, 1, 1);
    layout.addWidget(comboAgentFormat, 2, 1, 1, 2);
    layout.addWidget(labelSleep,       3, 0, 1, 1);
    layout.addWidget(textSleep,        3, 1, 1, 1);
    layout.addWidget(spinJitter,       3, 2, 1, 1);
    layout.addWidget(checkKilldate,    4, 0, 1, 1);
    layout.addWidget(dateKill,         4, 1, 1, 1);
    layout.addWidget(timeKill,         4, 2, 1, 1);
    layout.addWidget(checkWorkingTime, 5, 0, 1, 1);
    layout.addWidget(timeStart,        5, 1, 1, 1);
    layout.addWidget(timeFinish,       5, 2, 1, 1);
    layout.addWidget(labelRotation,    6, 0, 1, 1);
    layout.addWidget(comboRotation,    6, 1, 1, 2);
    layout.addWidget(checkIatHiding,   7, 0, 1, 3);
    layout.addWidget(group_proxy,      8, 0, 1, 3);
    layout.addWidget(spacer2,          9, 0, 1, 3);

    let container = form.create_container();
    container.put("arch",                comboArch);
    container.put("format",              comboAgentFormat);
    container.put("sleep",               textSleep);
    container.put("jitter",              spinJitter);
    container.put("is_killdate",         checkKilldate);
    container.put("kill_date",           dateKill);
    container.put("kill_time",           timeKill);
    container.put("is_workingtime",      checkWorkingTime);
    container.put("start_time",          timeStart);
    container.put("end_time",            timeFinish);
    container.put("iat_hiding",          checkIatHiding);
    container.put("use_proxy",           group_proxy);
    container.put("proxy_type",          comboProxyType);
    container.put("proxy_host",          textProxyServer);
    container.put("proxy_port",          spinProxyPort);
    container.put("proxy_username",      textProxyUsername);
    container.put("proxy_password",      textProxyPassword);
    container.put("rotation_mode",       comboRotation);

    let panel = form.create_panel();
    panel.setLayout(layout);

    return {
        ui_panel: panel,
        ui_container: container,
        ui_height: 420,
        ui_width: 520
    };
}
