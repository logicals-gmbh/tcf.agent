/*******************************************************************************
 * Copyright (c) 2009, 2011 Philippe Proulx, École Polytechnique de Montréal
 *                    Michael Sills-Lavoie, École Polytechnique de Montréal
 * and others. All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * and Eclipse Distribution License v1.0 which accompany this distribution.
 * The Eclipse Public License is available at
 * http://www.eclipse.org/legal/epl-v10.html
 * and the Eclipse Distribution License is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 * You may elect to redistribute this code under either of these licenses.
 *
 * Contributors:
 *     Philippe Proulx - initial plugins system
 *     Michael Sills-Lavoie - deterministic plugins loading order
 *     Michael Sills-Lavoie - plugin's shared functions
 *******************************************************************************/

/*
 * Plugins system.
 */

#if defined(__GNUC__) && !defined(_GNU_SOURCE)
#  define _GNU_SOURCE
#endif

#include <tcf/config.h>

#if ENABLE_Plugins

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if TARGET_UNIX
#include <dirent.h>
#include <dlfcn.h>
#elif TARGET_WINDOWS
#include <windows.h>
#include <tchar.h>
#endif
#include <errno.h>

#include <tcf/framework/trace.h>
#include <tcf/framework/myalloc.h>
#include <tcf/framework/plugins.h>
#include <tcf/framework/mdep-fs.h>

#define _QUOTEME(x)     #x
#define QUOTE(x)      _QUOTEME(x)

#if defined(_WIN32) || defined(__CYGWIN__)
#define PLUGINS_DEF_EXT     "dll"       /* Default plugins' extension */
#else
#define PLUGINS_DEF_EXT     "so"        /* Default plugins' extension */
#endif

typedef void (*InitFunc)(Protocol *, TCFBroadcastGroup *, void *);

const char *plugins_path = QUOTE(PATH_Plugins);

static void ** plugins_handles = NULL;
static size_t plugins_count = 0;
static struct function_entry {
    char * name;
    void * function;
} * function_entries = NULL;
static size_t function_entry_count = 0;

void plugins_set_path(char const* pluginsPath) {
    plugins_path = pluginsPath;
}

#if TARGET_WINDOWS
static void printGetLastErrorAsString(unsigned long errorMessageID) {
    char NoErrormessage[] = {"No error message has been recorded"};
    char* messageBuffer;

    //Get the error message, if any.
    if(errorMessageID == 0) {
        trace(LOG_PROTOCOL, "plugins error: No error message has been recorded");
    }

    size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    trace(LOG_PROTOCOL, "plugins error: %d ->%s", errorMessageID, messageBuffer);

    LocalFree(messageBuffer);
}

static void scandirWinFreeMem(int used, struct utf8_dirent **namelist, struct utf8_dirent *dirEntry, struct utf8_dirent *dirEntry2) {
    if (namelist) {
        for (int i = 0; i < used; i++) {
            free(namelist[i]);
        }
        free(namelist);
    }

    if (dirEntry) {
        free(dirEntry);
    }

    if (dirEntry2) {
        free(dirEntry2);
    }
}

static int errorScandirWinFreeMem(int used, struct utf8_dirent **namelist, struct utf8_dirent *dirEntry, struct utf8_dirent *dirEntry2) {
    scandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
    trace(LOG_PLUGIN, "ScandirWin error: function failed to allocate the requested block of memory");
    return -1;
}

/* Rewritten scandir() for Windows
 * ftp://ftp.acer.at/gpl/AS9100/GPL_AS9100/MPlayer-0.90/linux/scandir.c
 *
 * The scandir() function reads the directory dirname and builds an
 * array of pointers to directory entries using malloc(3).  It returns
 * the number of entries in the array.  A pointer to the array of
 * directory entries is stored in the location referenced by namelist.
 *
 * The select parameter is a pointer to a user supplied subroutine
 * which is called by scandir() to select which entries are to be
 * included in the array.  The select routine is passed a pointer to
 * a directory entry and should return a non-zero value if the
 * directory entry is to be included in the array.  If select is null,
 * then all the directory entries will be included.
 *
 * The compar parameter is a pointer to a user supplied subroutine
 * which is passed to qsort(3) to sort the completed array.  If this
 * pointer is null, the array is not sorted.
 */
static int scandirWin(const char *dirname, struct utf8_dirent ***ret_namelist,
        int (*select)(const struct utf8_dirent *),
        int (*compar)(const struct utf8_dirent **, const struct utf8_dirent **)) {
    int i, len;
    int used = 0, allocated = 0;
    char dirN[FILE_PATH_SIZE];
    struct utf8_dirent *dirEntry = NULL, *dirEntry2 = NULL;
    struct utf8_dirent **namelist = NULL;

    HANDLE hFind;
    WIN32_FIND_DATA fdFile;

    /* Prepare string for use with FindFile functions.  First, copy the
     * string to a buffer, then append '\*' to the directory name. */

    char pathAppendage[] = "\\*";
    size_t completeFilePathLength = strlen(dirname) + strlen(pathAppendage) + 1;

    if (completeFilePathLength > FILE_PATH_SIZE) {
        trace(LOG_PLUGIN, "ScandirWin error: The given path is to long! Length of the path=%d, FILE_PATH_SIZE=%d\n",
                strlen(dirname) + strlen(pathAppendage), FILE_PATH_SIZE);
        return -1;
    }

    strcpy(dirN, dirname);
    strcat(dirN, pathAppendage);

    hFind = FindFirstFile(dirN, &fdFile);

    if (INVALID_HANDLE_VALUE == hFind) {
        trace(LOG_PLUGIN, "ScandirWin error: Plugin directory not found (%d)", GetLastError());
        return -1;
    }

    if ((namelist = malloc((++allocated) * sizeof(struct dirent *))) == NULL) {
        return errorScandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
    }

    if ((dirEntry = malloc(sizeof(*dirEntry))) == NULL) {
        return errorScandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
    }

    do {
        if (!(fdFile.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            if ((strlen(fdFile.cFileName) + 1) > sizeof(dirEntry->d_name)) {
                return errorScandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
            }

            strcpy(dirEntry->d_name, fdFile.cFileName);

            if (select != NULL && !select(dirEntry)) {
                continue;
            }

            /* duplicate struct d_name dirEntry */
            len = offsetof(struct dirent, d_name) + strlen(dirEntry->d_name) + 1;

            if ((dirEntry2 = malloc(len)) == NULL) {
                return errorScandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
            }

            if (used >= allocated) {
                namelist = realloc(namelist, (++allocated) * sizeof(struct dirent *));

                if (!namelist) {
                    return errorScandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
                }
            }

            memcpy(dirEntry2, dirEntry, len);
            namelist[used++] = dirEntry2;
        }
    } while (FindNextFile(hFind, &fdFile) != 0);

    if (!GetLastError()) {
        scandirWinFreeMem(used, namelist, dirEntry, dirEntry2);
        trace(LOG_PLUGIN, "ScandirWin error: System error code: (%d)", GetLastError());
        return -1;
    }

    if (compar) {
        qsort(namelist, used, sizeof(struct dirent *),
                (int (*)(const void *, const void *)) compar);
    }

    *ret_namelist = namelist;

    free(dirEntry);

    return used;
}

/* convenience helper function for scandir's |compar()| function:
 * sort directory entries using strcoll(3)
 */
int alphasort(const void *_a, const void *_b) {
    struct dirent **a = (struct dirent **)_a;
    struct dirent **b = (struct dirent **)_b;
    return strcoll((*a)->d_name, (*b)->d_name);
}
#endif /* TARGET_WINDOWS */

static inline int plugins_ext_is(const char * ext, const char * filename) {
    const char * real_ext = strrchr(filename, '.');
    return real_ext != NULL && !strcmp(real_ext + 1, ext);
}

static int plugins_filter(const struct dirent * dirent) {
#if TARGET_UNIX
    if (!strcmp(dirent->d_name, ".") || !strcmp(dirent->d_name, ".."))
        return 0;
    if (!plugins_ext_is(PLUGINS_DEF_EXT, dirent->d_name) || dirent->d_type == DT_DIR)
        return 0;
#elif TARGET_WINDOWS
    if (!plugins_ext_is(PLUGINS_DEF_EXT, dirent->d_name))
        return 0;
#endif
    return 1;
}

#if defined(__GLIBC__) && (__GLIBC__ < 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ < 10))
static int plugins_ralphasort(const void * a, const void * b) {
#else
static int plugins_ralphasort(const struct dirent ** a, const struct dirent ** b) {
#endif
    return -alphasort(a, b);
}

int plugins_load(Protocol * proto, TCFBroadcastGroup * bcg) {
    struct dirent ** files;
    int file_count = -1;
    int ret = 0;

#if TARGET_UNIX
    file_count = scandir(plugins_path, &files, plugins_filter, plugins_ralphasort);
#elif TARGET_WINDOWS
    file_count = scandirWin(plugins_path, &files, plugins_filter, plugins_ralphasort);
#endif
    if (file_count < 0) {
        trace(LOG_PLUGIN, "plugins error: failed opening plugins directory \"%s\"", plugins_path);
        return -1;
    }

    while (file_count--) {
#if defined(_MSC_VER)
#define CUR_PLUGIN_PATH_LEN 1024
        char * cur_plugin_path = malloc(CUR_PLUGIN_PATH_LEN);
        if (!cur_plugin_path) {
            ret = -1;
            goto delete_cur_entry;
        }
        if (snprintf(cur_plugin_path, CUR_PLUGIN_PATH_LEN, "%s/%s", plugins_path, files[file_count]->d_name) == -1) {
            trace(LOG_PLUGIN, "plugins error: `snprintf' failed for plugin \"%s\"", files[file_count]->d_name);
            ret = -1;
            goto delete_cur_path;
        }
#else
        char * cur_plugin_path = NULL;
        if (asprintf(&cur_plugin_path, "%s/%s", plugins_path, files[file_count]->d_name) == -1) {
            trace(LOG_PLUGIN, "plugins error: `asprintf' failed for plugin \"%s\"", files[file_count]->d_name);
            ret = -1;
            goto delete_cur_entry;
        }
#endif
        if (plugin_init(cur_plugin_path, proto, bcg)) {
            trace(LOG_PLUGIN, "plugins error: unable to start plugin \"%s\"", cur_plugin_path);
            ret = -1;
            /* Continue to load the rest of plugins */
        }

        /* cur_plugin_path and files were allocated by asprintf() and scandir(),
         * and they should be released by free(), don't call loc_free() here. */
delete_cur_path:
        free(cur_plugin_path);
delete_cur_entry:
        free(files[file_count]);
    }
    free(files);

    return ret;
}

#if TARGET_UNIX
int plugin_init(const char * name, Protocol * proto, TCFBroadcastGroup * bcg) {
    void * handle;
    char * error;
    InitFunc init;

    /* Plugin loading: */
    trace(LOG_PLUGIN, "loading plugin \"%s\"", name);
    handle = dlopen(name, RTLD_LAZY);
    if (!handle) {
        trace(LOG_PLUGIN, "plugins error: \"%s\"", dlerror());
        return -1;
    }

    /* Plugin initialization: */
    init = (InitFunc)dlsym(handle, "tcf_init_plugin");
    if ((error = dlerror()) != NULL) {
        dlclose(handle);
        trace(LOG_PLUGIN, "plugins error: \"%s\"", error);
        return -1;
    }
    trace(LOG_PLUGIN, "initializing plugin \"%s\"", name);
    init(proto, bcg, NULL);

    /* Handles table update: */
    plugins_handles = (void **) loc_realloc(plugins_handles,
            ++plugins_count * sizeof(void *));
    plugins_handles[plugins_count - 1] = handle;

    return 0;
}
#elif TARGET_WINDOWS
int plugin_init(const char * name, Protocol * proto, TCFBroadcastGroup * bcg) {
    char * error;
    InitFunc init;

    void * handle;

    /* Plugin loading: */
    trace(LOG_PLUGIN, "loading plugin \"%s\"", name);

    handle = LoadLibrary(name);

    /* Check to see if the library was loaded successfully */
    if (!handle) {
        printGetLastErrorAsString(GetLastError());
        return -1;
    }

    /* Plugin initialization: */
    init = (InitFunc) GetProcAddress(handle, "tcf_init_plugin");

    if (!init) {
        printGetLastErrorAsString(GetLastError());
        FreeLibrary(handle);
        return -1;
    }

    trace(LOG_PLUGIN, "initializing plugin \"%s\"", name);
    init(proto, bcg, NULL);

    /* Handles table update: */
    plugins_handles = (void **) loc_realloc(plugins_handles,
            ++plugins_count * sizeof(void *));
    plugins_handles[plugins_count - 1] = handle;

    return 0;
}
#endif

int plugin_add_function(const char * name, void * function) {
    size_t i;

    if (!name || !function) return -EINVAL;

    /* Check if the function name already exists */
    for (i = 0; i < function_entry_count; ++i)
        if (!strcmp(name, function_entries[i].name))
            return -EEXIST;

    function_entries = (struct function_entry *) loc_realloc(function_entries,
            ++function_entry_count * sizeof(struct function_entry));

    function_entries[function_entry_count-1].function = function;
    function_entries[function_entry_count-1].name = loc_strdup(name);
    return 0;
}

void * plugin_get_function(const char * name) {
    size_t i;

    if (!name) return NULL;

    for (i = 0; i < function_entry_count; ++i)
        if (!strcmp(name, function_entries[i].name))
            return function_entries[i].function;

    return NULL;
}

int plugins_destroy(void) {
    size_t i;

    for (i = 0; i < plugins_count; ++i) {
#if TARGET_UNIX
        if (dlclose(plugins_handles[i])) {
            trace(LOG_PLUGIN, "plugins error: \"%s\"", dlerror());
        }
#elif TARGET_WINDOWS
        if (FreeLibrary(plugins_handles[i])) {
            trace(LOG_PLUGIN, "plugins error: \"%d\"", GetLastError());
        }
#endif
    }
    loc_free(plugins_handles);

    for (i = 0; i < function_entry_count; ++i)
        loc_free(function_entries[i].name);
    loc_free(function_entries);

    return 0;
}

#else  /* if ENABLE_Plugins */

/* The following functions are a simple workaround to have functions for
   the functions listed in the .def file. They must not be used */

void plugins_set_path(void) {
}

int plugins_load(void) {
    return -1;
}

int plugins_destroy(void) {
    return 0;
}

#endif  /* if ENABLE_Plugins */
