/*
 * mc_log_filter.c
 * MC 服务器日志过滤器 - 适配 Linux (CachyOS/Arch)
 * 修复版: 修复 strtok_r 破坏原字符串导致输出为空的 Bug
 *
 * 编译:
 *   icx -O3 -march=native -mtune=native -funroll-loops -o mc_log_filter mc_log_filter.c -lcrypto
 *   # 或 gcc: gcc -O2 -o mc_log_filter mc_log_filter.c -lcrypto
 *   # 无 OpenSSL: gcc -O2 -o mc_log_filter mc_log_filter.c
 *
 * 用法:
 *   ./mc_log_filter server.log                  # 输出到 filtered_<原名>_<哈希>.log
 *   ./mc_log_filter server.log output.log       # 指定输出文件
 *   cat server.log | ./mc_log_filter            # 管道模式
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_LINE_LEN 4096

/* ========== SHA256（优先 OpenSSL→自动 AVX-512，回退命令行） ========== */

#ifdef __linux__
#define HAVE_OPENSSL 0
#include <dlfcn.h>

typedef unsigned char* (*SHA256_func)(const unsigned char *, size_t, unsigned char *);

static int compute_sha256_openssl(const unsigned char *data, size_t len,
                                   unsigned char out[32]) {
    static void *handle = NULL;
    static SHA256_func sha256_func = NULL;

    if (!handle) {
        handle = dlopen("libcrypto.so.3", RTLD_LAZY | RTLD_LOCAL);
        if (!handle)
            handle = dlopen("libcrypto.so", RTLD_LAZY | RTLD_LOCAL);
        if (handle)
            sha256_func = (SHA256_func)dlsym(handle, "SHA256");
    }

    if (sha256_func) {
        sha256_func(data, len, out);
        return 0;
    }
    return -1;
}

static int compute_sha256_cmd(const unsigned char *data, size_t len,
                               unsigned char out[32]) {
    char tmpfile[256];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/mc_log_%d_%ld.tmp",
             getpid(), (long)time(NULL));

    FILE *f = fopen(tmpfile, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);

    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", tmpfile);
    FILE *fp = popen(cmd, "r");
    if (!fp) { unlink(tmpfile); return -1; }

    char hex[65];
    int ret = -1;
    if (fscanf(fp, "%64s", hex) == 1) {
        for (int i = 0; i < 32; i++)
            sscanf(hex + i * 2, "%2hhx", &out[i]);
        ret = 0;
    }
    pclose(fp);
    unlink(tmpfile);
    return ret;
}

static int compute_sha256(const unsigned char *data, size_t len,
                           unsigned char out[32]) {
    if (compute_sha256_openssl(data, len, out) == 0)
        return 0;
    return compute_sha256_cmd(data, len, out);
}

#else
/* macOS/其他 Unix */
static int compute_sha256(const unsigned char *data, size_t len,
                           unsigned char out[32]) {
    char tmpfile[256];
    snprintf(tmpfile, sizeof(tmpfile), "/tmp/mc_log_%d_%ld.tmp",
             getpid(), (long)time(NULL));
    FILE *f = fopen(tmpfile, "wb");
    if (!f) return -1;
    fwrite(data, 1, len, f);
    fclose(f);

    char cmd[512];
#ifdef __APPLE__
    snprintf(cmd, sizeof(cmd), "shasum -a 256 \"%s\" 2>/dev/null", tmpfile);
#else
    snprintf(cmd, sizeof(cmd), "sha256sum \"%s\" 2>/dev/null", tmpfile);
#endif
    FILE *fp = popen(cmd, "r");
    if (!fp) { unlink(tmpfile); return -1; }

    char hex[65];
    int ret = -1;
    if (fscanf(fp, "%64s", hex) == 1) {
        for (int i = 0; i < 32; i++)
            sscanf(hex + i * 2, "%2hhx", &out[i]);
        ret = 0;
    }
    pclose(fp);
    unlink(tmpfile);
    return ret;
}
#endif

static void bytes_to_hex(const unsigned char bytes[32], char hex[65]) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hex_chars[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[64] = '\0';
}

/* ========== 逐行迭代器（替代 strtok_r，不破坏原字符串） ========== */

typedef struct {
    const char *data;
    size_t len;
    size_t pos;
    char line[MAX_LINE_LEN];
} LineReader;

static void line_reader_init(LineReader *r, const char *data, size_t len) {
    r->data = data;
    r->len = len;
    r->pos = 0;
}

static const char* line_reader_next(LineReader *r) {
    if (r->pos >= r->len) return NULL;

    size_t start = r->pos;
    size_t end = start;
    while (end < r->len && r->data[end] != '\n') end++;

    size_t line_len = end - start;
    while (line_len > 0 && r->data[start + line_len - 1] == '\r')
        line_len--;

    size_t copy_len = line_len < MAX_LINE_LEN - 1 ? line_len : MAX_LINE_LEN - 1;
    memcpy(r->line, r->data + start, copy_len);
    r->line[copy_len] = '\0';

    r->pos = (end < r->len) ? end + 1 : r->len;
    return r->line;
}

/* ========== 过滤规则 ========== */

static int is_recipe_parsing_error(const char *line) {
    return strstr(line, "Parsing error loading recipe") != NULL;
}
static int is_drink_effect_error(const char *line) {
    return strstr(line, "Failed to parse drink effect data from") != NULL;
}
static int is_sublevel_saving(const char *line) {
    return strstr(line, "Saving sub-levels for level 'ServerLevel[create]'") != NULL;
}
static int is_simple_backup(const char *line) {
    return strstr(line, "[SimpleBackups/") != NULL;
}
static int is_datamap_missing(const char *line) {
    return strstr(line, "specified in data map for registry") != NULL;
}
static int is_curios_slot_error(const char *line) {
    return strstr(line, "is not a registered slot type!") != NULL &&
           strstr(line, "Curios API") != NULL;
}
static int is_biome_tag_warning(const char *line) {
    return strstr(line, "Not all defined tags for registry") != NULL &&
           strstr(line, "worldgen/biome") != NULL;
}
static int is_loaded_stats(const char *line) {
    if (!strstr(line, "Loaded ")) return 0;
    const char *patterns[] = {
        "Loaded 12370 recipes", "Added 5 recipes", "Removed 7620 recipe advancements",
        "Loaded 8721 advancements", "Loaded 4 fish conversions", "Loaded 11 curio slots",
        "Loaded 2 curio entities", "Loaded 29 flute songs", "Loaded 0 gear_sets",
        "Loaded 0 wanderer_trades", "Loaded 0 brewing_mixes",
        "Loaded 0 valid Replacements entries", "Replacement cache rebuilt",
        "Disabled reload-override mapping", NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strstr(line, patterns[i])) return 1;
    return 0;
}
static int is_mob_category_warning(const char *line) {
    return strstr(line, "was registered with") != NULL &&
           strstr(line, "mob category but was added under") != NULL;
}
static int is_fuel_info(const char *line) {
    return strstr(line, "FuelHandler") != NULL &&
           (strstr(line, "as Portable Generator Fuel") != NULL ||
            strstr(line, "as Motorboat Fuel") != NULL);
}
static int is_advancement_patch(const char *line) {
    return strstr(line, "Modified advancement") != NULL &&
           strstr(line, "patches") != NULL;
}
static int is_civil_unknown_warning(const char *line) {
    return strstr(line, "[civil-registry]") != NULL &&
           (strstr(line, "Unknown structure") || strstr(line, "Unknown block") ||
            strstr(line, "Unknown dimension") || strstr(line, "has no valid structures"));
}
static int is_cant_keep_up(const char *line) {
    return strstr(line, "Can't keep up! Is the server overloaded?") != NULL;
}
static int is_distcleaner_error(const char *line) {
    return strstr(line, "RuntimeDistCleaner") != NULL ||
           strstr(line, "Attempted to load class net/minecraft/client") != NULL;
}
static int is_lmft_error(const char *line) {
    return strstr(line, "Load My F***ing Tags") != NULL;
}
static int is_datapack_time(const char *line) {
    return strstr(line, "Initial datapack load took") != NULL;
}
static int is_stack_trace_line(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    if (strncmp(p, "at ", 3) == 0 || strncmp(p, "...", 3) == 0) return 1;
    if (strstr(line, "TRANSFORMER/") || strstr(line, "MC-BOOTSTRAP/")) return 1;
    if (strstr(line, "java.base/") || strstr(line, "cpw.mods.")) return 1;
    return 0;
}
static int is_caused_by(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    return strncmp(p, "Caused by:", 10) == 0;
}
static int is_suppressed(const char *line) {
    const char *p = line;
    while (*p == ' ' || *p == '\t') p++;
    return strncmp(p, "Suppressed:", 11) == 0;
}
static int is_main_info_noise(const char *line) {
    if (!strstr(line, "[main/INFO]")) return 0;
    const char *patterns[] = {
        "Loaded config", "Loading Replacements data", "Adding UDP server channel future",
        "Server UDP channel active", "Using epoll channel type",
        "Successfully reload", "Registered 0 gear_sets", "Registered 0 wanderer_trades",
        "Registered 0 brewing_mixes", NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strstr(line, patterns[i])) return 1;
    return 0;
}
static int is_main_warn_noise(const char *line) {
    if (!strstr(line, "[main/WARN]")) return 0;
    if (strstr(line, "Cannot find suitable entry for key=")) return 1;
    if (strstr(line, "Jupiter cannot resolve")) return 1;
    if (strstr(line, "ModernFix")) return 1;
    return 0;
}
static int is_main_error_noise(const char *line) {
    if (!strstr(line, "[main/ERROR]")) return 0;
    if (strstr(line, "Unknown registry key")) return 1;
    return 0;
}
static int is_server_warn_noise(const char *line) {
    if (!strstr(line, "[Server thread/WARN]")) return 0;
    if (strstr(line, "**** SERVER IS RUNNING IN OFFLINE/INSECURE MODE!")) return 1;
    if (strstr(line, "The server will make no attempt")) return 1;
    if (strstr(line, "While this makes the game possible")) return 1;
    if (strstr(line, "To change this, set")) return 1;
    if (strstr(line, "Detected ") && strstr(line, "that was registered with CREATURE")) return 1;
    if (strstr(line, "C2ME HookCompatibility")) return 1;
    if (strstr(line, "Certain optimizations may be disabled")) return 1;
    return 0;
}
static int is_server_error_noise(const char *line) {
    if (!strstr(line, "[Server thread/ERROR]")) return 0;
    if (strstr(line, "RuntimeDistCleaner")) return 1;
    if (strstr(line, "Failed to handle packet") && strstr(line, "suppressing error")) return 1;
    return 0;
}
static int is_barrel_roll_accept(const char *line) {
    return strstr(line, "accepted server config") != NULL &&
           strstr(line, "do_a_barrel_roll") != NULL;
}
static int is_fancymenu_join(const char *line) {
    return strstr(line, "FANCYMENU") != NULL;
}
static int is_ie_potion_line(const char *line) {
    return strstr(line, "Recipes for potions:") != NULL &&
           strstr(line, "immersiveengineering") != NULL;
}
static int is_mod_loading_noise(const char *line) {
    const char *patterns[] = {
        "Config spec loading complete", "Cloth Config loading complete",
        "Applied 17 data villager trades", "Failed to load custom color set definition",
        "Successfully loaded millstone bindable data", "Registering custom dispenser behaviors",
        "Loading Structurify config", "Structurify config loaded",
        "Loading Reservoirs", "Loading Distillation Recipes", "Loading Coker Recipes",
        "Loading High-Pressure Refinery Recipes", "Dispatching loading event for config",
        "Successfully loaded drink effect data with", "Disabling 1 structures",
        "Changed settings of", "Sending Replacements data", NULL
    };
    for (int i = 0; patterns[i]; i++)
        if (strstr(line, patterns[i])) return 1;
    return 0;
}

static int should_filter(const char *line) {
    if (line[0] == '\0') return 1;
    if (is_stack_trace_line(line)) return 1;
    if (is_caused_by(line)) return 1;
    if (is_suppressed(line)) return 1;
    if (is_recipe_parsing_error(line)) return 1;
    if (is_drink_effect_error(line)) return 1;
    if (is_sublevel_saving(line)) return 1;
    if (is_simple_backup(line)) return 1;
    if (is_datamap_missing(line)) return 1;
    if (is_curios_slot_error(line)) return 1;
    if (is_biome_tag_warning(line)) return 1;
    if (is_loaded_stats(line)) return 1;
    if (is_mob_category_warning(line)) return 1;
    if (is_fuel_info(line)) return 1;
    if (is_advancement_patch(line)) return 1;
    if (is_civil_unknown_warning(line)) return 1;
    if (is_mod_loading_noise(line)) return 1;
    if (is_cant_keep_up(line)) return 1;
    if (is_distcleaner_error(line)) return 1;
    if (is_lmft_error(line)) return 1;
    if (is_datapack_time(line)) return 1;
    if (is_main_info_noise(line)) return 1;
    if (is_main_warn_noise(line)) return 1;
    if (is_main_error_noise(line)) return 1;
    if (is_server_warn_noise(line)) return 1;
    if (is_server_error_noise(line)) return 1;
    if (is_barrel_roll_accept(line)) return 1;
    if (is_fancymenu_join(line)) return 1;
    if (is_ie_potion_line(line)) return 1;
    return 0;
}

/* ========== 时间戳提取 ========== */

static int extract_timestamp(const char *line, char *out, size_t out_size) {
    if (line[0] == '[') {
        const char *end = strchr(line + 1, ']');
        if (end && (size_t)(end - line) <= out_size) {
            int n = (int)(end - line - 1);
            memcpy(out, line + 1, n);
            out[n] = '\0';
            return 1;
        }
    }
    return 0;
}

/* ========== main ========== */

int main(int argc, char *argv[]) {
    const char *input_file = NULL;
    const char *output_file = NULL;
    int use_stdout = 0;

    if (argc < 2) {
        fprintf(stderr, "用法: %s <输入日志文件> [输出文件]\n", argv[0]);
        fprintf(stderr, "  - 省略输出: 自动生成 filtered_<原名>_<SHA256前缀>.log\n");
        fprintf(stderr, "  - '-' 作为输出: 输出到 stdout\n");
        return 1;
    }

    input_file = argv[1];

    if (argc >= 3) {
        if (strcmp(argv[2], "-") == 0)
            use_stdout = 1;
        else
            output_file = argv[2];
    }

    /* ========== 读取输入文件 ========== */
    FILE *fin = fopen(input_file, "rb");
    if (!fin) {
        fprintf(stderr, "错误: 无法打开 '%s'\n", input_file);
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    long file_size = ftell(fin);
    rewind(fin);

    if (file_size <= 0) {
        fprintf(stderr, "错误: 文件为空\n");
        fclose(fin);
        return 1;
    }

    char *file_content = (char*)malloc((size_t)file_size + 1);
    if (!file_content) {
        fprintf(stderr, "错误: 内存不足\n");
        fclose(fin);
        return 1;
    }

    size_t read_size = fread(file_content, 1, (size_t)file_size, fin);
    file_content[read_size] = '\0';
    fclose(fin);

    /* ========== 计算 SHA256 ========== */
    unsigned char hash[32];
    char hash_hex[65];
    memset(hash_hex, '0', 64);
    hash_hex[64] = '\0';

    if (compute_sha256((unsigned char*)file_content, read_size, hash) == 0) {
        bytes_to_hex(hash, hash_hex);
    }

    /* ========== 过滤：先写入临时文件 ========== */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/mc_log_filter_%d_%ld.tmp",
             getpid(), (long)time(NULL));

    FILE *ftmp = fopen(tmp_path, "wb");
    if (!ftmp) {
        fprintf(stderr, "错误: 无法创建临时文件\n");
        free(file_content);
        return 1;
    }

    LineReader reader;
    line_reader_init(&reader, file_content, read_size);

    int kept = 0, filtered = 0;
    char first_time[16] = "";
    char last_time[16] = "";
    int first_line = 1;

    const char *line;
    while ((line = line_reader_next(&reader)) != NULL) {
        if (should_filter(line)) {
            filtered++;
        } else {
            char ts[16];
            if (extract_timestamp(line, ts, sizeof(ts) - 1)) {
                if (first_line) {
                    strncpy(first_time, ts, 15);
                    first_time[15] = '\0';
                    first_line = 0;
                }
                strncpy(last_time, ts, 15);
                last_time[15] = '\0';
            }
            fprintf(ftmp, "%s\n", line);
            kept++;
        }
    }

    fclose(ftmp);
    free(file_content);

    /* ========== 确定输出文件名 ========== */
    char auto_filename[512];
    const char *final_output;

    if (use_stdout) {
        final_output = "(stdout)";
    } else if (output_file) {
        final_output = output_file;
    } else {
        const char *p = input_file + strlen(input_file) - 1;
        while (p > input_file && p[-1] != '/') p--;

        char basename[256];
        strncpy(basename, p, sizeof(basename) - 1);
        basename[sizeof(basename) - 1] = '\0';

        char *dot = strrchr(basename, '.');
        if (dot) *dot = '\0';

        snprintf(auto_filename, sizeof(auto_filename),
                 "filtered_%s_%.16s.log", basename, hash_hex);
        final_output = auto_filename;
    }

    /* ========== 生成最终输出 ========== */
    time_t now = time(NULL);
    struct tm *tm_now = localtime(&now);
    char time_str[64] = "unknown";
    if (tm_now)
        strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_now);

    FILE *fout;
    if (use_stdout) {
        fout = stdout;
    } else {
        fout = fopen(final_output, "w");
        if (!fout) {
            fprintf(stderr, "错误: 无法写入 '%s'\n", final_output);
            unlink(tmp_path);
            return 1;
        }
    }

    /* 写入 YAML 头 */
    fprintf(fout, "---\n");
    fprintf(fout, "type: mc_server_filtered_log\n");
    fprintf(fout, "source_file: \"%s\"\n", input_file);
    fprintf(fout, "filter_time: \"%s\"\n", time_str);
    fprintf(fout, "content_hash: \"%s\"\n", hash_hex);
    fprintf(fout, "hash_algorithm: \"SHA256\"\n");
    fprintf(fout, "filter_version: \"2.1\"\n");
    fprintf(fout, "time_range_start: \"%s\"\n", first_time[0] ? first_time : "N/A");
    fprintf(fout, "time_range_end: \"%s\"\n", last_time[0] ? last_time : "N/A");
    fprintf(fout, "kept_lines: %d\n", kept);
    fprintf(fout, "filtered_lines: %d\n", filtered);
    fprintf(fout, "---\n");

    /* 追加过滤后的内容 */
    FILE *ftmp_r = fopen(tmp_path, "rb");
    if (ftmp_r) {
        char buf[65536];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), ftmp_r)) > 0)
            fwrite(buf, 1, n, fout);
        fclose(ftmp_r);
    }

    if (!use_stdout) fclose(fout);
    unlink(tmp_path);

    /* 打印摘要 */
    printf("┌─────────────────────────────────────────────┐\n");
    printf("│  MC 日志过滤器 v2.1 (OpenSSL AVX-512)       │\n");
    printf("├─────────────────────────────────────────────┤\n");
    printf("│  输入: %-30s  │\n", input_file);
    printf("│  大小: %-10ld 字节                         │\n", file_size);
    printf("│  输出: %-30s  │\n", final_output);
    printf("│  哈希: %.16s...                             │\n", hash_hex);
    printf("│  保留: %-5d 行    过滤: %-5d 行            │\n", kept, filtered);
    if (kept + filtered > 0)
        printf("│  过滤率: %-5.1f%%                              │\n",
               100.0 * filtered / (kept + filtered));
    printf("│  时间: %s                 │\n", first_time[0] ? first_time : "N/A");
    printf("│  至  : %s                 │\n", last_time[0] ? last_time : "N/A");
    printf("└─────────────────────────────────────────────┘\n");

    return 0;
}
