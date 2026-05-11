/*
 * mc_log_filter.c
 * MC 服务器日志过滤器 - 优化版 (ICX + AVX-512)
 *
 * 系统: CachyOS / Arch Linux
 * 编译器: Intel ICX (oneAPI DPC++/C++ Compiler)
 * CPU 特性: AVX-512 (AVX512F, AVX512BW, AVX512VBMI)
 *
 * 编译:
 *   icx -O3 -march=native -mtune=native -funroll-loops -o mc_log_filter mc_log_filter.c
 *
 * 用法:
 *   ./mc_log_filter server.log                  # 输出到 filtered_<原名>_<哈希>.log
 *   ./mc_log_filter server.log output.log       # 指定输出文件
 *   ./mc_log_filter - < output.log              # stdin 模式
 *   ./mc_log_filter server.log -                # 输出到 stdout
 */

/* ========== 必须放在所有头文件之前 ========== */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/mman.h>    /* memfd_create, MFD_CLOEXEC */
#include <unistd.h>
#include <immintrin.h>   /* AVX-512 intrinsics */
#include <stdint.h>
#include <errno.h>

#define MAX_LINE_LEN 4096
#define SHA256_HEX_SIZE 65
#define SHA256_BIN_SIZE 32

/* ========== 编译时检测 AVX-512 支持 ========== */
#if defined(__AVX512F__) && defined(__AVX512BW__)
#define HAVE_AVX512 1
#else
#define HAVE_AVX512 0
#warning "AVX-512 not detected at compile time. Use -march=native with ICX."
#endif

/* ========== SIMD 加速字符串搜索 (AVX-512) ========== */

/**
 * 使用 AVX-512 快速查找子串（strstr 的加速版）
 * 对长度 ≤ 32 的 pattern 使用 SIMD，否则回退到 strstr
 */
static inline const char* simd_strstr(const char *haystack, const char *needle) {
    #if HAVE_AVX512
    size_t nlen = strlen(needle);
    if (nlen == 0) return haystack;
    if (nlen > 32) return strstr(haystack, needle);

    size_t hlen = strlen(haystack);
    if (nlen > hlen) return NULL;

    /* 加载 needle 的第一个字节到广播寄存器 */
    __m512i first = _mm512_set1_epi8((char)needle[0]);

    for (size_t i = 0; i <= hlen - nlen; i++) {
        /* 用 AVX-512 一次比较 64 字节，找第一个字符匹配的位置 */
        size_t j = i;
        while (j <= hlen - nlen) {
            __m512i chunk = _mm512_loadu_si512((const __m512i*)(haystack + j));
            __mmask64 mask = _mm512_cmpeq_epi8_mask(chunk, first);

            if (mask != 0) {
                /* 找到第一个匹配的位置 */
                unsigned long bit;
                #if defined(__AVX512VBMI__)
                /* AVX-512 VBMI: 用 compress 快速定位 */
                j += _tzcnt_u64(mask);
                #else
                j += __builtin_ctzll(mask);
                #endif

                /* 检查完整匹配 */
                if (j <= hlen - nlen) {
                    if (memcmp(haystack + j, needle, nlen) == 0)
                        return haystack + j;
                    j++;
                }
            } else {
                j += 64;
            }
        }
        return NULL;
    }
    return NULL;
    #else
    (void)haystack; (void)needle;
    return strstr(haystack, needle);
    #endif
}

/* 别名，方便阅读 */
#define str_find simd_strstr

/* ========== SHA256（调用系统 sha256sum，避免 OpenSSL 依赖） ========== */

static int compute_sha256(const unsigned char *data, size_t len,
                          unsigned char out[32]) {
    /* 用 memfd_create + 管道，避免磁盘 I/O */
    int fd = -1;
    int ret = -1;

    /* 创建内存文件 */
    fd = memfd_create("mc_log_sha", MFD_CLOEXEC);
    if (fd < 0) goto fallback;

    FILE *f = fdopen(fd, "wb");
    if (!f) { close(fd); goto fallback; }

    if (fwrite(data, 1, len, f) != len) {
        fclose(f);
        goto fallback;
    }
    /* 重新定位到开头 */
    rewind(f);

    /* 构建命令：从 /proc/self/fd/<fd> 读取 */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "sha256sum /proc/self/fd/%d 2>/dev/null", fd);

    FILE *fp = popen(cmd, "r");
    if (!fp) { fclose(f); goto fallback; }

    char hex[65];
    if (fscanf(fp, "%64s", hex) == 1) {
        for (int i = 0; i < 32; i++)
            sscanf(hex + i * 2, "%2hhx", &out[i]);
        ret = 0;
    }

    pclose(fp);
    fclose(f);
    return ret;

    fallback:
    /* 传统临时文件方案 */
    {
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
        if (fscanf(fp, "%64s", hex) == 1) {
            for (int i = 0; i < 32; i++)
                sscanf(hex + i * 2, "%2hhx", &out[i]);
            ret = 0;
        }
        pclose(fp);
        unlink(tmpfile);
    }
    return ret;
                          }

                          static void bytes_to_hex(const unsigned char bytes[32], char hex[65]) {
                              static const char hex_chars[] = "0123456789abcdef";
                              for (int i = 0; i < 32; i++) {
                                  hex[i * 2]     = hex_chars[bytes[i] >> 4];
                                  hex[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
                              }
                              hex[64] = '\0';
                          }

                          /* ========== 逐行迭代器（替代 strtok_r，避免破坏原字符串） ========== */

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
                              r->line[0] = '\0';
                          }

                          static const char* line_reader_next(LineReader *r) {
                              if (r->pos >= r->len) return NULL;

                              size_t start = r->pos;
                              size_t end = start;

                              /* 找换行符 */
                              while (end < r->len && r->data[end] != '\n') end++;

                              /* 计算行长度（去掉 \r） */
                              size_t line_len = end - start;
                              while (line_len > 0 && r->data[start + line_len - 1] == '\r')
                                  line_len--;

                              /* 复制到缓冲区 */
                              size_t copy_len = line_len < MAX_LINE_LEN - 1 ? line_len : MAX_LINE_LEN - 1;
                              memcpy(r->line, r->data + start, copy_len);
                              r->line[copy_len] = '\0';

                              /* 跳过换行符 */
                              r->pos = (end < r->len) ? end + 1 : r->len;

                              return r->line;
                          }

                          /* ========== 过滤规则（优化版，用 SIMD strstr） ========== */

                          static int is_recipe_parsing_error(const char *line) {
                              return str_find(line, "Parsing error loading recipe") != NULL;
                          }
                          static int is_drink_effect_error(const char *line) {
                              return str_find(line, "Failed to parse drink effect data from") != NULL;
                          }
                          static int is_sublevel_saving(const char *line) {
                              return str_find(line, "Saving sub-levels for level 'ServerLevel[create]'") != NULL;
                          }
                          static int is_simple_backup(const char *line) {
                              return str_find(line, "[SimpleBackups/") != NULL;
                          }
                          static int is_datamap_missing(const char *line) {
                              return str_find(line, "specified in data map for registry") != NULL;
                          }
                          static int is_curios_slot_error(const char *line) {
                              return str_find(line, "is not a registered slot type!") != NULL &&
                              str_find(line, "Curios API") != NULL;
                          }
                          static int is_biome_tag_warning(const char *line) {
                              return str_find(line, "Not all defined tags for registry") != NULL &&
                              str_find(line, "worldgen/biome") != NULL;
                          }
                          static int is_loaded_stats(const char *line) {
                              if (!str_find(line, "Loaded ")) return 0;
                              const char *p[] = {
                                  "Loaded 12370 recipes","Added 5 recipes","Removed 7620 recipe advancements",
                                  "Loaded 8721 advancements","Loaded 4 fish conversions","Loaded 11 curio slots",
                                  "Loaded 2 curio entities","Loaded 29 flute songs","Loaded 0 gear_sets",
                                  "Loaded 0 wanderer_trades","Loaded 0 brewing_mixes",
                                  "Loaded 0 valid Replacements entries","Replacement cache rebuilt",
                                  "Disabled reload-override mapping", NULL
                              };
                              for (int i = 0; p[i]; i++) if (str_find(line, p[i])) return 1;
                              return 0;
                          }
                          static int is_mob_category_warning(const char *line) {
                              return str_find(line, "was registered with") != NULL &&
                              str_find(line, "mob category but was added under") != NULL;
                          }
                          static int is_fuel_info(const char *line) {
                              return str_find(line, "FuelHandler") != NULL &&
                              (str_find(line, "as Portable Generator Fuel") != NULL ||
                              str_find(line, "as Motorboat Fuel") != NULL);
                          }
                          static int is_advancement_patch(const char *line) {
                              return str_find(line, "Modified advancement") != NULL &&
                              str_find(line, "patches") != NULL;
                          }
                          static int is_civil_unknown_warning(const char *line) {
                              return str_find(line, "[civil-registry]") != NULL &&
                              (str_find(line, "Unknown structure") || str_find(line, "Unknown block") ||
                              str_find(line, "Unknown dimension") || str_find(line, "has no valid structures"));
                          }
                          static int is_cant_keep_up(const char *line) {
                              return str_find(line, "Can't keep up! Is the server overloaded?") != NULL;
                          }
                          static int is_distcleaner_error(const char *line) {
                              return str_find(line, "RuntimeDistCleaner") != NULL ||
                              str_find(line, "Attempted to load class net/minecraft/client") != NULL;
                          }
                          static int is_lmft_error(const char *line) {
                              return str_find(line, "Load My F***ing Tags") != NULL;
                          }
                          static int is_datapack_time(const char *line) {
                              return str_find(line, "Initial datapack load took") != NULL;
                          }
                          static int is_stack_trace_line(const char *line) {
                              const char *p = line;
                              while (*p == ' ' || *p == '\t') p++;
                              if (strncmp(p, "at ", 3) == 0 || strncmp(p, "...", 3) == 0) return 1;
                              if (str_find(line, "TRANSFORMER/") || str_find(line, "MC-BOOTSTRAP/")) return 1;
                              if (str_find(line, "java.base/") || str_find(line, "cpw.mods.")) return 1;
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
                              if (!str_find(line, "[main/INFO]")) return 0;
                              const char *p[] = {
                                  "Loaded config","Loading Replacements data","Adding UDP server channel future",
                                  "Server UDP channel active","Using epoll channel type",
                                  "Successfully reload","Registered 0 gear_sets","Registered 0 wanderer_trades",
                                  "Registered 0 brewing_mixes",NULL
                              };
                              for (int i = 0; p[i]; i++) if (str_find(line, p[i])) return 1;
                              return 0;
                          }
                          static int is_main_warn_noise(const char *line) {
                              if (!str_find(line, "[main/WARN]")) return 0;
                              if (str_find(line, "Cannot find suitable entry for key=")) return 1;
                              if (str_find(line, "Jupiter cannot resolve")) return 1;
                              if (str_find(line, "ModernFix")) return 1;
                              return 0;
                          }
                          static int is_main_error_noise(const char *line) {
                              if (!str_find(line, "[main/ERROR]")) return 0;
                              if (str_find(line, "Unknown registry key")) return 1;
                              return 0;
                          }
                          static int is_server_warn_noise(const char *line) {
                              if (!str_find(line, "[Server thread/WARN]")) return 0;
                              if (str_find(line, "**** SERVER IS RUNNING IN OFFLINE/INSECURE MODE!")) return 1;
                              if (str_find(line, "The server will make no attempt")) return 1;
                              if (str_find(line, "While this makes the game possible")) return 1;
                              if (str_find(line, "To change this, set")) return 1;
                              if (str_find(line, "Detected ") && str_find(line, "that was registered with CREATURE")) return 1;
                              if (str_find(line, "C2ME HookCompatibility")) return 1;
                              if (str_find(line, "Certain optimizations may be disabled")) return 1;
                              return 0;
                          }
                          static int is_server_error_noise(const char *line) {
                              if (!str_find(line, "[Server thread/ERROR]")) return 0;
                              if (str_find(line, "RuntimeDistCleaner")) return 1;
                              if (str_find(line, "Failed to handle packet") && str_find(line, "suppressing error")) return 1;
                              return 0;
                          }
                          static int is_barrel_roll_accept(const char *line) {
                              return str_find(line, "accepted server config") != NULL &&
                              str_find(line, "do_a_barrel_roll") != NULL;
                          }
                          static int is_fancymenu_join(const char *line) {
                              return str_find(line, "FANCYMENU") != NULL;
                          }
                          static int is_ie_potion_line(const char *line) {
                              return str_find(line, "Recipes for potions:") != NULL &&
                              str_find(line, "immersiveengineering") != NULL;
                          }
                          static int is_mod_loading_noise(const char *line) {
                              const char *p[] = {
                                  "Config spec loading complete","Cloth Config loading complete",
                                  "Applied 17 data villager trades","Failed to load custom color set definition",
                                  "Successfully loaded millstone bindable data","Registering custom dispenser behaviors",
                                  "Loading Structurify config","Structurify config loaded",
                                  "Loading Reservoirs","Loading Distillation Recipes","Loading Coker Recipes",
                                  "Loading High-Pressure Refinery Recipes","Dispatching loading event for config",
                                  "Successfully loaded drink effect data with","Disabling 1 structures",
                                  "Changed settings of","Sending Replacements data",NULL
                              };
                              for (int i = 0; p[i]; i++) if (str_find(line, p[i])) return 1;
                              return 0;
                          }

                          static int should_filter(const char *line) {
                              if (line[0] == '\0' || line[0] == '\n' || line[0] == '\r') return 1;
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
                                  if (end && (size_t)(end - line) <= out_size + 1) {
                                      int n = (int)(end - line - 1);
                                      memcpy(out, line + 1, n);
                                      out[n] = '\0';
                                      return 1;
                                  }
                              }
                              return 0;
                          }

                          /* ========== 简化输出 ========== */

                          typedef struct {
                              char *data;
                              size_t len;
                              size_t cap;
                          } DynBuf;

                          static int dynbuf_init(DynBuf *b, size_t initial) {
                              b->data = malloc(initial);
                              if (!b->data) return -1;
                              b->len = 0;
                              b->cap = initial;
                              return 0;
                          }

                          static int dynbuf_append(DynBuf *b, const char *s, size_t len) {
                              if (b->len + len > b->cap) {
                                  size_t new_cap = b->cap * 2;
                                  if (new_cap < b->len + len) new_cap = b->len + len + 65536;
                                  char *new_data = realloc(b->data, new_cap);
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

                          /* ========== main ========== */

                          int main(int argc, char *argv[]) {
                              const char *input_file = NULL;
                              const char *output_file = NULL;
                              int use_stdout = 0;
                              int pipe_mode = 0;

                              /* 解析参数 */
                              if (argc < 2) {
                                  fprintf(stderr, "用法: %s <输入日志文件> [输出文件]\n", argv[0]);
                                  fprintf(stderr, "  - 作为输入: 从文件读取\n");
                                  fprintf(stderr, "  - '-' 作为输入: 从 stdin 读取\n");
                                  fprintf(stderr, "  - 省略输出: 自动生成 filtered_<原名>_<SHA256前缀>.log\n");
                                  fprintf(stderr, "  - '-' 作为输出: 输出到 stdout\n");
                                  return 1;
                              }

                              if (strcmp(argv[1], "-") == 0) {
                                  pipe_mode = 1;
                              } else {
                                  input_file = argv[1];
                              }

                              if (argc >= 3) {
                                  if (strcmp(argv[2], "-") == 0) {
                                      use_stdout = 1;
                                  } else {
                                      output_file = argv[2];
                                  }
                              }

                              /* ========== 读取输入 ========== */
                              unsigned char *file_content = NULL;
                              long file_size = 0;

                              if (pipe_mode) {
                                  /* 从 stdin 读取（动态增长） */
                                  DynBuf buf;
                                  if (dynbuf_init(&buf, 65536) != 0) {
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

                                  /* 转移所有权 */
                                  file_content = (unsigned char*)buf.data;
                                  file_size = (long)buf.len;
                                  buf.data = NULL;  /* 防止被 free */
                              } else {
                                  /* 从文件读取 */
                                  FILE *fin = fopen(input_file, "rb");
                                  if (!fin) {
                                      fprintf(stderr, "错误: 无法打开 '%s': %s\n", input_file, strerror(errno));
                                      return 1;
                                  }

                                  fseek(fin, 0, SEEK_END);
                                  file_size = ftell(fin);
                                  rewind(fin);

                                  if (file_size <= 0) {
                                      fprintf(stderr, "错误: 文件为空或读取失败\n");
                                      fclose(fin);
                                      return 1;
                                  }

                                  file_content = (unsigned char*)malloc((size_t)file_size + 1);
                                  if (!file_content) {
                                      fprintf(stderr, "错误: 内存不足 (%ld 字节)\n", file_size);
                                      fclose(fin);
                                      return 1;
                                  }

                                  size_t read_size = fread(file_content, 1, (size_t)file_size, fin);
                                  file_content[read_size] = '\0';
                                  fclose(fin);

                                  if ((long)read_size != file_size) {
                                      fprintf(stderr, "警告: 读取大小不匹配 (%zu vs %ld)\n", read_size, file_size);
                                      file_size = (long)read_size;
                                  }
                              }

                              /* ========== 计算 SHA256 ========== */
                              unsigned char hash[32];
                              char hash_hex[SHA256_HEX_SIZE];
                              memset(hash_hex, '0', SHA256_HEX_SIZE - 1);
                              hash_hex[SHA256_HEX_SIZE - 1] = '\0';

                              if (file_size > 0) {
                                  if (compute_sha256(file_content, (size_t)file_size, hash) == 0) {
                                      bytes_to_hex(hash, hash_hex);
                                  }
                              }

                              /* ========== 过滤（单次遍历，直接输出到文件） ========== */
                              /* 策略：先过滤到一个临时文件，然后加上 YAML 头后输出到最终文件 */

                              /* 构建临时文件名 */
                              char tmp_output[512];
                              snprintf(tmp_output, sizeof(tmp_output), "/tmp/mc_log_filter_%d_%ld.tmp",
                                       getpid(), (long)time(NULL));

                              FILE *ftmp = fopen(tmp_output, "wb");
                              if (!ftmp) {
                                  fprintf(stderr, "错误: 无法创建临时文件 '%s'\n", tmp_output);
                                  free(file_content);
                                  return 1;
                              }

                              LineReader reader;
                              line_reader_init(&reader, (const char*)file_content, (size_t)file_size);

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

                              /* ========== 生成最终输出 ========== */
                              time_t now = time(NULL);
                              struct tm *tm_now = localtime(&now);
                              char time_str[64] = "unknown";
                              if (tm_now)
                                  strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_now);

                              /* 确定输出文件名 */
                              char auto_filename[512];
                              const char *final_output = NULL;

                              if (use_stdout) {
                                  final_output = "(stdout)";
                              } else if (output_file) {
                                  final_output = output_file;
                              } else {
                                  /* 自动生成文件名 */
                                  const char *p;
                                  if (pipe_mode) {
                                      p = "stdin";
                                  } else {
                                      p = input_file + strlen(input_file) - 1;
                                      while (p > input_file && p[-1] != '/') p--;
                                  }

                                  char basename[256];
                                  strncpy(basename, p, sizeof(basename) - 1);
                                  basename[sizeof(basename) - 1] = '\0';

                                  if (!pipe_mode) {
                                      char *dot = strrchr(basename, '.');
                                      if (dot) *dot = '\0';
                                  }

                                  snprintf(auto_filename, sizeof(auto_filename),
                                           "filtered_%s_%.16s.log", basename, hash_hex);
                                  final_output = auto_filename;
                              }

                              /* 打开最终输出 */
                              FILE *fout = NULL;
                              if (use_stdout) {
                                  fout = stdout;
                              } else {
                                  fout = fopen(final_output, "w");
                                  if (!fout) {
                                      fprintf(stderr, "错误: 无法写入 '%s': %s\n", final_output, strerror(errno));
                                      unlink(tmp_output);
                                      free(file_content);
                                      return 1;
                                  }
                              }

                              /* 写入 YAML 头 */
                              fprintf(fout, "---\n");
                              fprintf(fout, "type: mc_server_filtered_log\n");
                              if (input_file)
                                  fprintf(fout, "source_file: \"%s\"\n", input_file);
                              else
                                  fprintf(fout, "source_file: \"(stdin)\"\n");
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
                              FILE *ftmp_r = fopen(tmp_output, "rb");
                              if (ftmp_r) {
                                  char buf[65536];
                                  size_t n;
                                  while ((n = fread(buf, 1, sizeof(buf), ftmp_r)) > 0) {
                                      fwrite(buf, 1, n, fout);
                                  }
                                  fclose(ftmp_r);
                              }

                              if (!use_stdout) fclose(fout);

                              /* 清理临时文件 */
                              unlink(tmp_output);
                              free(file_content);

                              /* ========== 打印摘要 ========== */
                              printf("┌─────────────────────────────────────────────┐\n");
                              printf("│  MC 日志过滤器 v2.1 (AVX-512)               │\n");
                              printf("├─────────────────────────────────────────────┤\n");
                              if (input_file)
                                  printf("│  输入: %-30s  │\n", input_file);
                              else
                                  printf("│  输入: %-30s  │\n", "(stdin)");
                              printf("│  大小: %-10ld 字节                         │\n", (long)file_size);
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
