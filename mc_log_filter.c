/*
 * mc_log_filter.c
 * MC 服务器日志过滤器 - 全平台通用版
 * 
 * 功能: 过滤 Minecraft 服务器日志中的噪音信息
 * 
 * 编译:
 *   Linux/macOS:  gcc -O2 -o mc_log_filter mc_log_filter.c
 *   Windows:      gcc -O2 -o mc_log_filter.exe mc_log_filter.c  (MinGW)
 *   ICX:          icx -O3 -march=native -o mc_log_filter mc_log_filter.c
 *   
 * 用法:
 *   ./mc_log_filter server.log                  # 输出到 filtered_<原名>_<哈希>.log
 *   ./mc_log_filter server.log output.log       # 指定输出文件
 *   ./mc_log_filter server.log -                # 输出到 stdout
 *   cat server.log | ./mc_log_filter -          # 管道模式
 *   ./mc_log_filter - - < server.log            # 双管道模式
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>

/* ========== 平台适配 ========== */
#ifdef _WIN32
    #include <windows.h>
    #include <direct.h>
    #define PLATFORM_WINDOWS 1
    #define strncasecmp _strnicmp
    #define snprintf _snprintf
    #define unlink _unlink
    #define mkdir(path, mode) _mkdir(path)
    static inline void get_tmp_path(char *buf, size_t size, const char *prefix) {
        char tmpdir[MAX_PATH];
        GetTempPathA(MAX_PATH, tmpdir);
        snprintf(buf, size, "%s%s_%d_%ld.tmp", tmpdir, prefix,
                 GetCurrentProcessId(), (long)time(NULL));
    }
#else
    #include <unistd.h>
    #include <sys/stat.h>
    #define PLATFORM_WINDOWS 0
    static inline void get_tmp_path(char *buf, size_t size, const char *prefix) {
        snprintf(buf, size, "/tmp/%s_%d_%ld.tmp", prefix,
                 getpid(), (long)time(NULL));
    }
#endif

#define MAX_LINE_LEN 4096
#define MAX_FILE_PATH 1024
#define SHA256_HEX_SIZE 65

/* ========== SHA256 实现（纯 C，无外部依赖） ========== */

typedef struct {
    unsigned char data[64];
    unsigned int datalen;
    unsigned long long bitlen;
    unsigned int state[8];
} SHA256_CTX;

#define ROTLEFT(a,b) (((a) << (b)) | ((a) >> (32-(b))))
#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const unsigned int k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const unsigned char data[]) {
    unsigned int a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j+1] << 16) | (data[j+2] << 8) | (data[j+3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const unsigned char data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, unsigned char hash[32]) {
    unsigned int i = ctx->datalen;
    ctx->data[i++] = 0x80;
    if (i >= 56) {
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        i = 0;
    }
    while (i < 56) ctx->data[i++] = 0x00;
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = (unsigned char)(ctx->bitlen);
    ctx->data[62] = (unsigned char)(ctx->bitlen >> 8);
    ctx->data[61] = (unsigned char)(ctx->bitlen >> 16);
    ctx->data[60] = (unsigned char)(ctx->bitlen >> 24);
    ctx->data[59] = (unsigned char)(ctx->bitlen >> 32);
    ctx->data[58] = (unsigned char)(ctx->bitlen >> 40);
    ctx->data[57] = (unsigned char)(ctx->bitlen >> 48);
    ctx->data[56] = (unsigned char)(ctx->bitlen >> 56);
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (unsigned char)(ctx->state[0] >> (24 - i * 8));
        hash[i + 4]  = (unsigned char)(ctx->state[1] >> (24 - i * 8));
        hash[i + 8]  = (unsigned char)(ctx->state[2] >> (24 - i * 8));
        hash[i + 12] = (unsigned char)(ctx->state[3] >> (24 - i * 8));
        hash[i + 16] = (unsigned char)(ctx->state[4] >> (24 - i * 8));
        hash[i + 20] = (unsigned char)(ctx->state[5] >> (24 - i * 8));
        hash[i + 24] = (unsigned char)(ctx->state[6] >> (24 - i * 8));
        hash[i + 28] = (unsigned char)(ctx->state[7] >> (24 - i * 8));
    }
}

/* ========== 纯 C SHA256 计算 ========== */

static void sha256_compute(const unsigned char *data, size_t len, unsigned char hash[32]) {
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
}

static void bytes_to_hex(const unsigned char bytes[32], char hex[65]) {
    static const char hex_chars[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        hex[i * 2]     = hex_chars[bytes[i] >> 4];
        hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
    }
    hex[64] = '\0';
}

/* ========== 逐行读取器（不修改原字符串） ========== */

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
    while (line_len > 0 && (r->data[start + line_len - 1] == '\r' ||
                            r->data[start + line_len - 1] == '\n'))
        line_len--;
    
    size_t copy_len = line_len < MAX_LINE_LEN - 1 ? line_len : MAX_LINE_LEN - 1;
    memcpy(r->line, r->data + start, copy_len);
    r->line[copy_len] = '\0';
    
    r->pos = (end < r->len) ? end + 1 : r->len;
    return r->line;
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
           (strstr(line, "Unknown structure") != NULL ||
            strstr(line, "Unknown block") != NULL ||
            strstr(line, "Unknown dimension") != NULL ||
            strstr(line, "has no valid structures") != NULL);
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
    if (strstr(line, "TRANSFORMER/") != NULL || strstr(line, "MC-BOOTSTRAP/") != NULL) return 1;
    if (strstr(line, "java.base/") != NULL || strstr(line, "cpw.mods.") != NULL) return 1;
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

/* ========== 动态缓冲区（用于管道模式） ========== */

typedef struct {
    char *data;
    size_t len;
    size_t cap;
} DynBuf;

static int dynbuf_init(DynBuf *b) {
    b->cap = 65536;
    b->data = (char*)malloc(b->cap);
    if (!b->data) return -1;
    b->len = 0;
    return 0;
}

static int dynbuf_append(DynBuf *b, const char *s, size_t len) {
    if (b->len + len > b->cap) {
        size_t new_cap = b->cap * 2;
        if (new_cap < b->len + len) new_cap = b->len + len + 65536;
        char *new_data = (char*)realloc(b->data, new_cap);
        if (!new_data) return -1;
        b->data = new_data;
        b->cap = new_cap;
    }
    memcpy(b->data + b->len, s, len);
    b->len += len;
    return 0;
}

static void dynbuf_free(DynBuf *b) {
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ========== 文件读取（读整个文件到内存） ========== */

static char* read_file(const char *path, long *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    rewind(f);
    
    if (size <= 0) {
        fclose(f);
        return NULL;
    }
    
    char *content = (char*)malloc((size_t)size + 1);
    if (!content) {
        fclose(f);
        return NULL;
    }
    
    size_t read = fread(content, 1, (size_t)size, f);
    content[read] = '\0';
    fclose(f);
    
    *out_size = (long)read;
    return content;
}

/* ========== 跨平台 UTF-8 控制台输出 ========== */

#ifdef _WIN32
static void setup_console(void) {
    SetConsoleOutputCP(CP_UTF8);
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(hOut, &mode)) {
        mode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, mode);
    }
}
#else
static void setup_console(void) {}
#endif

/* ========== 主函数 ========== */

int main(int argc, char *argv[]) {
    setup_console();
    
    const char *input_file = NULL;
    const char *output_file = NULL;
    int use_stdout = 0;
    int pipe_mode = 0;
    
    /* 解析参数 */
    if (argc < 2) {
        fprintf(stderr, "MC 服务器日志过滤器 - 全平台通用版\n");
        fprintf(stderr, "\n用法:\n");
        fprintf(stderr, "  %s <输入日志> [输出文件]\n", argv[0]);
        fprintf(stderr, "\n参数:\n");
        fprintf(stderr, "  输入日志    过滤的日志文件，或 '-' 从 stdin 读取\n");
        fprintf(stderr, "  输出文件    输出文件，省略则自动命名，'-' 输出到 stdout\n");
        fprintf(stderr, "\n示例:\n");
        fprintf(stderr, "  %s server.log\n", argv[0]);
        fprintf(stderr, "  %s server.log filtered.log\n", argv[0]);
        fprintf(stderr, "  cat server.log | %s -\n", argv[0]);
        fprintf(stderr, "  %s server.log -\n", argv[0]);
        return 1;
    }
    
    if (strcmp(argv[1], "-") == 0)
        pipe_mode = 1;
    else
        input_file = argv[1];
    
    if (argc >= 3) {
        if (strcmp(argv[2], "-") == 0)
            use_stdout = 1;
        else
            output_file = argv[2];
    }
    
    /* ========== 读取输入 ========== */
    char *file_content = NULL;
    long file_size = 0;
    
    if (pipe_mode) {
        DynBuf buf;
        if (dynbuf_init(&buf) != 0) {
            fprintf(stderr, "错误: 内存不足\n");
            return 1;
        }
        
        char tmp[8192];
        size_t n;
        while ((n = fread(tmp, 1, sizeof(tmp), stdin)) > 0) {
            if (dynbuf_append(&buf, tmp, n) != 0) {
                fprintf(stderr, "错误: 内存不足\n");
                dynbuf_free(&buf);
                return 1;
            }
        }
        
        if (buf.len == 0) {
            fprintf(stderr, "错误: stdin 为空\n");
            dynbuf_free(&buf);
            return 1;
        }
        
        file_content = buf.data;
        file_size = (long)buf.len;
        buf.data = NULL;  /* 防止被 free */
    } else {
        file_content = read_file(input_file, &file_size);
        if (!file_content) {
            fprintf(stderr, "错误: 无法打开 '%s'\n", input_file);
            return 1;
        }
    }
    
    /* ========== 计算 SHA256 ========== */
    unsigned char hash[32];
    char hash_hex[SHA256_HEX_SIZE];
    memset(hash_hex, '0', 64);
    hash_hex[64] = '\0';
    
    sha256_compute((unsigned char*)file_content, (size_t)file_size, hash);
    bytes_to_hex(hash, hash_hex);
    
    /* ========== 过滤到临时文件 ========== */
    char tmp_path[MAX_FILE_PATH];
    get_tmp_path(tmp_path, sizeof(tmp_path), "mc_log_filter");
    
    FILE *ftmp = fopen(tmp_path, "wb");
    if (!ftmp) {
        fprintf(stderr, "错误: 无法创建临时文件\n");
        free(file_content);
        return 1;
    }
    
    LineReader reader;
    line_reader_init(&reader, file_content, (size_t)file_size);
    
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
    char auto_filename[MAX_FILE_PATH];
    const char *final_output;
    
    if (use_stdout) {
        final_output = "(stdout)";
    } else if (output_file) {
        final_output = output_file;
    } else {
        const char *p = input_file + strlen(input_file) - 1;
        while (p > input_file && p[-1] != '/' && p[-1] != '\\') p--;
        
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
    
    /* YAML 头 */
    fprintf(fout, "---\n");
    fprintf(fout, "type: mc_server_filtered_log\n");
    fprintf(fout, "source_file: \"%s\"\n", input_file ? input_file : "(stdin)");
    fprintf(fout, "filter_time: \"%s\"\n", time_str);
    fprintf(fout, "content_hash: \"%s\"\n", hash_hex);
    fprintf(fout, "hash_algorithm: \"SHA256\"\n");
    fprintf(fout, "filter_version: \"2.1\"\n");
    fprintf(fout, "time_range_start: \"%s\"\n", first_time[0] ? first_time : "N/A");
    fprintf(fout, "time_range_end: \"%s\"\n", last_time[0] ? last_time : "N/A");
    fprintf(fout, "kept_lines: %d\n", kept);
    fprintf(fout, "filtered_lines: %d\n", filtered);
    fprintf(fout, "---\n");
    
    /* 追加内容 */
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
    
    /* 摘要 */
    printf("+-----------------------------------------------+\n");
    printf("|  MC 日志过滤器 v2.1 (纯 C, 全平台)             |\n");
    printf("+-----------------------------------------------+\n");
    printf("|  输入: %-36s |\n", input_file ? input_file : "(stdin)");
    printf("|  大小: %-10ld 字节                           |\n", file_size);
    printf("|  输出: %-36s |\n", final_output);
    printf("|  哈希: %.16s...                               |\n", hash_hex);
    printf("|  保留: %-5d 行    过滤: %-5d 行              |\n", kept, filtered);
    if (kept + filtered > 0)
        printf("|  过滤率: %-5.1f%%                                |\n",
               100.0 * filtered / (kept + filtered));
    printf("|  时间: %-16s                         |\n", first_time[0] ? first_time : "N/A");
    printf("|  至  : %-16s                         |\n", last_time[0] ?
