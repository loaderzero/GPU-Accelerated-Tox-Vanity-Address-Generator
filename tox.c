#define _GNU_SOURCE

#include <ctype.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <stdatomic.h>
#define CL_TARGET_OPENCL_VERSION 210

#if defined(_WIN32)
#  define WIN32_LEAN_AND_MEAN
#  define NOMINMAX
#  include <windows.h>
#  include <process.h>
#else
#  include <sys/types.h>
#  include <sys/stat.h>
#  include <sys/sysinfo.h>
#  include <unistd.h>
#  include <fcntl.h>
#  include <pthread.h>
#endif

#include <assert.h>
#include <errno.h>
#include <signal.h>

#include <CL/cl.h>

#include <sodium/utils.h>

#include <tox/tox.h>


typedef unsigned int uint;
typedef unsigned long ulong;


// ----------- version -----------
#define VERSION_MAJOR 0
#define VERSION_MINOR 99
#define VERSION_PATCH 0
static const char global_version_string[] = "0.99.0";
// ----------- version -----------

#define CURRENT_LOG_LEVEL 9 

#define CLEAR(x) memset(&(x), 0, sizeof(x))

#if defined(_WIN32)
#  define c_sleep(x) Sleep(x)
#  define getpid _getpid
#else
#  define c_sleep(x) usleep(1000*(x))
#endif


const char *log_filename = "tox_vanity_addr_gen.log";
FILE *logfile = NULL;

static atomic_int found_global = ATOMIC_VAR_INIT(0);

// ----------- OpenCL Globals -----------
cl_platform_id platform_id = NULL;
cl_device_id device_id = NULL;
cl_context context = NULL;
cl_command_queue command_queue = NULL;
cl_program program = NULL;
cl_kernel kernel = NULL;

cl_mem wanted_prefix_buf = NULL;
cl_mem found_key_buf = NULL;
cl_mem found_flag_buf = NULL;

uint8_t gpu_found_private_key[32] = {0};
char device_name_str[128] = {0};

size_t gpu_global_work_size = (1 << 16);
uint gpu_iterations_per_launch = (1 << 12);
ulong gpu_current_nonce = 0;
// ------------------------------------

// Modes
typedef enum {
    MODE_CPU,
    MODE_GPU,
    MODE_HYBRID
} run_mode_t;

static size_t portable_strnlen(const char *s, size_t max_len)
{
    size_t i = 0;
    if (!s) {
        return 0;
    }
    while (i < max_len && s[i] != '\0') {
        ++i;
    }
    return i;
}

static void print_usage(const char *progname)
{
    printf("Usage: %s [OPTIONS]\n", progname);
    printf("  -v, --version                        show version\n");
    printf("  -h, --help                           print this help and exit\n");
    printf("  -a, --address <prefix>               Desired vanity address prefix (e.g., \"DEADBEEF\")\n");
    printf("  -t, --threads <num>                  Number of CPU threads to use (default: logical CPU cores)\n");
    printf("  -m, --mode <cpu|gpu|hybrid>          Operation mode (default: hybrid)\n");
    printf("  -n, --nospam <value>                 Nospam value (integer or hex, e.g., 0x12345678)\n");
}

static int parse_mode_string(const char *value, run_mode_t *mode)
{
    if (!value || !mode) {
        return -1;
    }
    if (strcmp(value, "cpu") == 0) {
        *mode = MODE_CPU;
        return 0;
    }
    if (strcmp(value, "gpu") == 0) {
        *mode = MODE_GPU;
        return 0;
    }
    if (strcmp(value, "hybrid") == 0) {
        *mode = MODE_HYBRID;
        return 0;
    }
    return -1;
}

static char *duplicate_uppercase_prefix(const char *value, uint *out_len)
{
    if (!value) {
        return NULL;
    }
    size_t len = portable_strnlen(value, TOX_ADDRESS_SIZE * 2 + 1);
    if (len > TOX_ADDRESS_SIZE * 2) {
        return NULL;
    }
    char *result = (char *)calloc(1, TOX_ADDRESS_SIZE * 2 + 1);
    if (!result) {
        return NULL;
    }
    strncpy(result, value, TOX_ADDRESS_SIZE * 2);
    result[TOX_ADDRESS_SIZE * 2] = '\0';
    for (size_t i = 0; i < len; ++i) {
        result[i] = (char)toupper((unsigned char)result[i]);
    }
    if (out_len) {
        *out_len = (uint)len;
    }
    return result;
}


#if defined(_WIN32)
typedef HANDLE portable_thread_t;
#else
typedef pthread_t portable_thread_t;
#endif

typedef void *(*thread_func_t)(void *);

typedef struct thread_start_context {
    thread_func_t func;
    void *arg;
} thread_start_context_t;

#if defined(_WIN32)
static unsigned __stdcall portable_thread_trampoline(void *param)
{
    thread_start_context_t *ctx = (thread_start_context_t *)param;
    thread_func_t fn = ctx->func;
    void *arg = ctx->arg;
    free(ctx);
    if (fn) {
        fn(arg);
    }
    return 0U;
}
#endif

static int portable_thread_create(portable_thread_t *thread, thread_func_t func, void *arg)
{
    if (!thread || !func) {
        return EINVAL;
    }

#if defined(_WIN32)
    thread_start_context_t *ctx = (thread_start_context_t *)malloc(sizeof(thread_start_context_t));
    if (!ctx) {
        return ENOMEM;
    }
    ctx->func = func;
    ctx->arg = arg;
    uintptr_t handle = _beginthreadex(NULL, 0, portable_thread_trampoline, ctx, 0, NULL);
    if (handle == 0) {
        int err = errno;
        free(ctx);
        if (err == 0) {
            err = EAGAIN;
        }
        return err;
    }
    *thread = (HANDLE)handle;
    return 0;
#else
    return pthread_create(thread, NULL, func, arg);
#endif
}

static int portable_thread_join(portable_thread_t thread)
{
#if defined(_WIN32)
    DWORD wait_result = WaitForSingleObject(thread, INFINITE);
    if (wait_result == WAIT_FAILED) {
        DWORD err = GetLastError();
        CloseHandle(thread);
        if (err == ERROR_INVALID_HANDLE) {
            return ESRCH;
        }
        return EINVAL;
    }
    CloseHandle(thread);
    return 0;
#else
    return pthread_join(thread, NULL);
#endif
}

static int get_logical_cpu_count(void)
{
#if defined(_WIN32)
    SYSTEM_INFO sysinfo;
    GetNativeSystemInfo(&sysinfo);
    if (sysinfo.dwNumberOfProcessors == 0) {
        return 1;
    }
    return (int)sysinfo.dwNumberOfProcessors;
#else
    int count = get_nprocs();
    return count > 0 ? count : 1;
#endif
}


void dbg(int level, const char *fmt, ...)
{
    char *level_and_format = NULL;

    if (fmt == NULL || strlen(fmt) < 1 || !logfile)
    {
        return;
    }

    if ((level < 0) || (level > 9))
    {
        level = 0;
    }

    // Allocate enough space for level char + ':' + format string + null terminator
    level_and_format = malloc(strlen(fmt) + 3);
    if (!level_and_format)
    {
        fprintf(stderr, "dbg: Failed to allocate memory for log string.\n");
        return;
    }

    // Construct "L:fmt" string
    level_and_format[1] = ':';
    if (level == 0) level_and_format[0] = 'E';
    else if (level == 1) level_and_format[0] = 'W';
    else if (level == 2) level_and_format[0] = 'I';
    else level_and_format[0] = 'D';
    strcpy(level_and_format + 2, fmt);

    if (level <= CURRENT_LOG_LEVEL)
    {
        va_list ap;
        va_start(ap, fmt);
        vfprintf(logfile, level_and_format, ap);
        va_end(ap);
    }

    free(level_and_format);
}

void get_my_toxid(Tox *tox, char *toxid_str)
{
    uint8_t tox_id_bin[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox, tox_id_bin);

    char tox_id_hex_local[TOX_ADDRESS_SIZE * 2 + 1];
    sodium_bin2hex(tox_id_hex_local, sizeof(tox_id_hex_local), tox_id_bin, TOX_ADDRESS_SIZE);

    for (size_t i = 0; i < (TOX_ADDRESS_SIZE * 2); i ++)
    {
        tox_id_hex_local[i] = toupper(tox_id_hex_local[i]);
    }

    snprintf(toxid_str, (size_t)(TOX_ADDRESS_SIZE * 2 + 1), "%s", (const char *)tox_id_hex_local);
}

void print_tox_id(char *tox_id_hex)
{
    fprintf(stderr, "-> %s\n", tox_id_hex);
}

int check_if_found(Tox *tox, char *wanted_address_string)
{
    char tox_id_hex[TOX_ADDRESS_SIZE * 2 + 1];
    get_my_toxid(tox, tox_id_hex);

    if (strncmp(tox_id_hex, wanted_address_string, strlen(wanted_address_string)) == 0)
    {
        return 1;
    }
    else
    {
        return 0;
    }
}

time_t get_unix_time(void)
{
    return time(NULL);
}

void yieldcpu(uint32_t ms)
{
#if defined(_WIN32)
    Sleep(ms);
#else
    usleep(1000 * ms);
#endif
}

void sigint_handler(int signo)
{
    if (signo == SIGINT)
    {
        fprintf(stderr, "received SIGINT, pid=%d. Setting found_global to stop workers.\n", getpid());
        dbg(2, "Received SIGINT, pid=%d. Setting found_global to stop workers.\n", getpid());
        atomic_store(&found_global, 1); // Устанавливаем флаг, чтобы все потоки и GPU остановились
    }
}

void update_savedata_file(const Tox *tox, char *savedata_filename)
{
    size_t size = tox_get_savedata_size(tox);
    uint8_t *savedata = (uint8_t *)calloc(1, size);
    if (!savedata) {
        fprintf(stderr, "Failed to allocate memory for savedata.\n");
        dbg(0, "Failed to allocate memory for savedata.\n");
        return;
    }
    tox_get_savedata(tox, savedata);
    FILE *f = fopen(savedata_filename, "wb");
    if (!f) {
        fprintf(stderr, "Failed to open file %s for writing: %s\n", savedata_filename, strerror(errno));
        dbg(0, "Failed to open file %s for writing: %s\n", savedata_filename, strerror(errno));
        free(savedata);
        return;
    }
    fwrite(savedata, size, 1, f);
    fclose(f);
    free(savedata);
    fprintf(stderr, "Saved Tox profile to: %s\n", savedata_filename);
    dbg(2, "Saved Tox profile to: %s\n", savedata_filename);
}

// Function to get OpenCL error string
const char *clGetErrorString(cl_int error) {
    switch(error){
        case CL_SUCCESS: return "CL_SUCCESS";
        case CL_DEVICE_NOT_FOUND: return "CL_DEVICE_NOT_FOUND";
        case CL_DEVICE_NOT_AVAILABLE: return "CL_DEVICE_NOT_AVAILABLE";
        case CL_COMPILER_NOT_AVAILABLE: return "CL_COMPILER_NOT_AVAILABLE";
        case CL_MEM_OBJECT_ALLOCATION_FAILURE: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case CL_OUT_OF_RESOURCES: return "CL_OUT_OF_RESOURCES";
        case CL_OUT_OF_HOST_MEMORY: return "CL_OUT_OF_HOST_MEMORY";
        case CL_PROFILING_INFO_NOT_AVAILABLE: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case CL_MEM_COPY_OVERLAP: return "CL_MEM_COPY_OVERLAP";
        case CL_IMAGE_FORMAT_MISMATCH: return "CL_IMAGE_FORMAT_MISMATCH";
        case CL_IMAGE_FORMAT_NOT_SUPPORTED: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case CL_BUILD_PROGRAM_FAILURE: return "CL_BUILD_PROGRAM_FAILURE";
        case CL_MAP_FAILURE: return "CL_MAP_FAILURE";
        case CL_MISALIGNED_SUB_BUFFER_OFFSET: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case CL_COMPILE_PROGRAM_FAILURE: return "CL_COMPILE_PROGRAM_FAILURE";
        case CL_LINKER_NOT_AVAILABLE: return "CL_LINKER_NOT_AVAILABLE";
        case CL_LINK_PROGRAM_FAILURE: return "CL_LINK_PROGRAM_FAILURE";
        case CL_DEVICE_PARTITION_FAILED: return "CL_DEVICE_PARTITION_FAILED";
        case CL_KERNEL_ARG_INFO_NOT_AVAILABLE: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";
        case CL_INVALID_VALUE: return "CL_INVALID_VALUE";
        case CL_INVALID_DEVICE_TYPE: return "CL_INVALID_DEVICE_TYPE";
        case CL_INVALID_PLATFORM: return "CL_INVALID_PLATFORM";
        case CL_INVALID_DEVICE: return "CL_INVALID_DEVICE";
        case CL_INVALID_CONTEXT: return "CL_INVALID_CONTEXT";
        case CL_INVALID_QUEUE_PROPERTIES: return "CL_INVALID_QUEUE_PROPERTIES";
        case CL_INVALID_COMMAND_QUEUE: return "CL_INVALID_COMMAND_QUEUE";
        case CL_INVALID_HOST_PTR: return "CL_INVALID_HOST_PTR";
        case CL_INVALID_MEM_OBJECT: return "CL_INVALID_MEM_OBJECT";
        case CL_INVALID_IMAGE_FORMAT_DESCRIPTOR: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case CL_INVALID_IMAGE_SIZE: return "CL_INVALID_IMAGE_SIZE";
        case CL_INVALID_SAMPLER: return "CL_INVALID_SAMPLER";
        case CL_INVALID_BINARY: return "CL_INVALID_BINARY";
        case CL_INVALID_BUILD_OPTIONS: return "CL_INVALID_BUILD_OPTIONS";
        case CL_INVALID_PROGRAM: return "CL_INVALID_PROGRAM";
        case CL_INVALID_PROGRAM_EXECUTABLE: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case CL_INVALID_KERNEL_NAME: return "CL_INVALID_KERNEL_NAME";
        case CL_INVALID_KERNEL_DEFINITION: return "CL_INVALID_KERNEL_DEFINITION";
        case CL_INVALID_KERNEL: return "CL_INVALID_KERNEL";
        case CL_INVALID_ARG_INDEX: return "CL_INVALID_ARG_INDEX";
        case CL_INVALID_ARG_VALUE: return "CL_INVALID_ARG_VALUE";
        case CL_INVALID_ARG_SIZE: return "CL_INVALID_ARG_SIZE";
        case CL_INVALID_KERNEL_ARGS: return "CL_INVALID_KERNEL_ARGS";
        case CL_INVALID_WORK_DIMENSION: return "CL_INVALID_WORK_DIMENSION";
        case CL_INVALID_WORK_GROUP_SIZE: return "CL_INVALID_WORK_GROUP_SIZE";
        case CL_INVALID_WORK_ITEM_SIZE: return "CL_INVALID_WORK_ITEM_SIZE";
        case CL_INVALID_GLOBAL_OFFSET: return "CL_INVALID_GLOBAL_OFFSET";
        case CL_INVALID_EVENT_WAIT_LIST: return "CL_INVALID_EVENT_WAIT_LIST";
        case CL_INVALID_EVENT: return "CL_INVALID_EVENT";
        case CL_INVALID_OPERATION: return "CL_INVALID_OPERATION";
        case CL_INVALID_GL_OBJECT: return "CL_INVALID_GL_OBJECT";
        case CL_INVALID_BUFFER_SIZE: return "CL_INVALID_BUFFER_SIZE";
        case CL_INVALID_MIP_LEVEL: return "CL_INVALID_MIP_LEVEL";
        case CL_INVALID_GLOBAL_WORK_SIZE: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case CL_INVALID_PROPERTY: return "CL_INVALID_PROPERTY";
        case CL_INVALID_IMAGE_DESCRIPTOR: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case CL_INVALID_COMPILER_OPTIONS: return "CL_INVALID_COMPILER_OPTIONS";
        case CL_INVALID_LINKER_OPTIONS: return "CL_INVALID_LINKER_OPTIONS";
        case CL_INVALID_DEVICE_PARTITION_COUNT: return "CL_INVALID_DEVICE_PARTITION_COUNT";
        default: return "Unknown OpenCL Error";
    }
}

// Macro for checking OpenCL errors
#define CHECK_CL_ERROR(err, msg) \
    if (err != CL_SUCCESS) { \
        fprintf(stderr, "OpenCL Error (%s): %s at %s:%d\n", clGetErrorString(err), msg, __FILE__, __LINE__); \
        dbg(0, "OpenCL Error (%s): %s at %s:%d\n", clGetErrorString(err), msg, __FILE__, __LINE__); \
        return -1; \
    }

// Function to read OpenCL kernel source from file
char* read_kernel_source(const char* filename) {
    FILE* fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open kernel file '%s': %s\n", filename, strerror(errno));
        dbg(0, "Failed to open kernel file '%s': %s\n", filename, strerror(errno));
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *source_str = malloc(fsize + 1);
    if (!source_str) {
        fclose(fp);
        fprintf(stderr, "Memory allocation failed for kernel source.\n");
        dbg(0, "Memory allocation failed for kernel source.\n");
        return NULL;
    }
    fread(source_str, 1, fsize, fp);
    fclose(fp);
    source_str[fsize] = '\0';
    return source_str;
}

// Function to set up OpenCL environment
int setup_opencl(char* wanted_address_string, uint wanted_len, uint nospam_val, ulong initial_rng_nonce) {
    cl_int err;
    char *kernel_source = NULL;
    size_t kernel_source_len;

    // 1. Get Platform ID
    err = clGetPlatformIDs(1, &platform_id, NULL);
          
        if (err == -1001) { // CL_PLATFORM_NOT_FOUND_KHR
        fprintf(stderr, "OpenCL platform not found. Ensure OpenCL drivers are installed.\n");
        dbg(0, "OpenCL platform not found.\n");
        return -1;
    }
    CHECK_CL_ERROR(err, "clGetPlatformIDs");

    // 2. Get Device ID (GPU)
    err = clGetDeviceIDs(platform_id, CL_DEVICE_TYPE_GPU, 1, &device_id, NULL);
    if (err == CL_DEVICE_NOT_FOUND) {
        fprintf(stderr, "No OpenCL GPU device found. Ensure GPU drivers are installed or try different device type.\n");
        dbg(0, "No OpenCL GPU device found.\n");
        return -1;
    }
    CHECK_CL_ERROR(err, "clGetDeviceIDs");

    clGetDeviceInfo(device_id, CL_DEVICE_NAME, sizeof(device_name_str), device_name_str, NULL);
    dbg(2, "Using OpenCL Device: %s\n", device_name_str);
    fprintf(stderr, "Using OpenCL Device: %s\n", device_name_str);


    // 3. Create OpenCL Context
    context = clCreateContext(NULL, 1, &device_id, NULL, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateContext");

    // 4. Create Command Queue
    command_queue = clCreateCommandQueue(context, device_id, 0, &err);
    CHECK_CL_ERROR(err, "clCreateCommandQueue");

    // 5. Load kernel source
    kernel_source = read_kernel_source("vanity_kernel.cl");
    if (!kernel_source) return -1;
    kernel_source_len = strlen(kernel_source);

    // 6. Create and Compile OpenCL program
    program = clCreateProgramWithSource(context, 1, (const char **)&kernel_source,
                                        (const size_t *)&kernel_source_len, &err);
    CHECK_CL_ERROR(err, "clCreateProgramWithSource");

    err = clBuildProgram(program, 1, &device_id, NULL, NULL, NULL);
    if (err != CL_SUCCESS) {
        size_t log_size;
        clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, 0, NULL, &log_size);
        char *build_log = malloc(log_size);
        if (build_log) {
            clGetProgramBuildInfo(program, device_id, CL_PROGRAM_BUILD_LOG, log_size, build_log, NULL);
            fprintf(stderr, "OpenCL Build Error:\n%s\n", build_log);
            dbg(0, "OpenCL Build Error:\n%s\n", build_log);
            free(build_log);
        } else {
            fprintf(stderr, "OpenCL Build Error: Failed to allocate memory for log.\n");
            dbg(0, "OpenCL Build Error: Failed to allocate memory for log.\n");
        }
        free(kernel_source);
        return -1;
    }
    free(kernel_source);

    // 7. Create Kernel
    kernel = clCreateKernel(program, "find_vanity_address", &err);
    CHECK_CL_ERROR(err, "clCreateKernel");

    // 8. Create Buffers on device (GPU)
    wanted_prefix_buf = clCreateBuffer(context, CL_MEM_READ_ONLY | CL_MEM_COPY_HOST_PTR,
                                       wanted_len + 1, wanted_address_string, &err); // +1 for null terminator
    CHECK_CL_ERROR(err, "clCreateBuffer for wanted_prefix_buf");

    found_key_buf = clCreateBuffer(context, CL_MEM_WRITE_ONLY, 32, NULL, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer for found_key_buf");

    // Initialize found_flag on GPU to 0
    uint initial_found_flag = 0;
    found_flag_buf = clCreateBuffer(context, CL_MEM_READ_WRITE | CL_MEM_COPY_HOST_PTR,
                                    sizeof(uint), &initial_found_flag, &err);
    CHECK_CL_ERROR(err, "clCreateBuffer for found_flag_buf");

    gpu_current_nonce = initial_rng_nonce;
    if (gpu_global_work_size == 0) {
        gpu_global_work_size = (1 << 16);
    }
    if (gpu_iterations_per_launch == 0) {
        gpu_iterations_per_launch = (1 << 12);
    }

    // 9. Set Kernel Arguments
    err = clSetKernelArg(kernel, 0, sizeof(cl_mem), &wanted_prefix_buf); CHECK_CL_ERROR(err, "clSetKernelArg 0 (wanted_prefix)");
    err = clSetKernelArg(kernel, 1, sizeof(uint), &wanted_len);         CHECK_CL_ERROR(err, "clSetKernelArg 1 (wanted_len)");
    err = clSetKernelArg(kernel, 2, sizeof(cl_mem), &found_key_buf);    CHECK_CL_ERROR(err, "clSetKernelArg 2 (found_key_buf)");
    err = clSetKernelArg(kernel, 3, sizeof(cl_mem), &found_flag_buf);   CHECK_CL_ERROR(err, "clSetKernelArg 3 (found_flag_buf)");
    err = clSetKernelArg(kernel, 4, sizeof(uint), &nospam_val);         CHECK_CL_ERROR(err, "clSetKernelArg 4 (nospam)");
    err = clSetKernelArg(kernel, 5, sizeof(ulong), &gpu_current_nonce); CHECK_CL_ERROR(err, "clSetKernelArg 5 (start_nonce)");
    err = clSetKernelArg(kernel, 6, sizeof(uint), &gpu_iterations_per_launch); CHECK_CL_ERROR(err, "clSetKernelArg 6 (iterations)");

    return 0;
}

// Function to launch GPU search
int run_gpu_search() {
    cl_int err;

    err = clSetKernelArg(kernel, 5, sizeof(ulong), &gpu_current_nonce);
    CHECK_CL_ERROR(err, "clSetKernelArg 5 (start_nonce)");
    err = clSetKernelArg(kernel, 6, sizeof(uint), &gpu_iterations_per_launch);
    CHECK_CL_ERROR(err, "clSetKernelArg 6 (iterations)");

    err = clEnqueueNDRangeKernel(command_queue, kernel, 1, NULL, &gpu_global_work_size, NULL, 0, NULL, NULL);
    CHECK_CL_ERROR(err, "clEnqueueNDRangeKernel");
    clFlush(command_queue); // Send commands to device
    dbg(2, "GPU kernel launched with global_work_size: %zu, iterations: %u, start_nonce: %lu\n",
        gpu_global_work_size, gpu_iterations_per_launch, gpu_current_nonce);

    gpu_current_nonce += (ulong)gpu_global_work_size * (ulong)gpu_iterations_per_launch;

    return 0;
}

// Function to release OpenCL resources
void cleanup_opencl() {
    if (wanted_prefix_buf) clReleaseMemObject(wanted_prefix_buf);
    if (found_key_buf) clReleaseMemObject(found_key_buf);
    if (found_flag_buf) clReleaseMemObject(found_flag_buf);
    if (kernel) clReleaseKernel(kernel);
    if (program) clReleaseProgram(program);
    if (command_queue) clReleaseCommandQueue(command_queue);
    if (context) clReleaseContext(context);
    gpu_current_nonce = 0;
    dbg(9, "OpenCL resources released.\n");
}

// Function to save the Tox profile found by GPU
// This function will PRINT the found private key in HEX.
// It WILL NOT generate a .dat file matching this key directly
// due to complexities of Tox savedata format from raw private keys.
void save_tox_profile_from_private_key(const uint8_t *private_key) {
    char private_key_hex[32 * 2 + 1]; // 32 bytes * 2 chars/byte + null
    sodium_bin2hex(private_key_hex, sizeof(private_key_hex), private_key, 32);
    for (size_t i = 0; i < 32 * 2; i++) {
        private_key_hex[i] = toupper(private_key_hex[i]);
    }
    fprintf(stderr, "\n");
    fprintf(stderr, "=========================================================\n");
    fprintf(stderr, "!!! ADDRESS FOUND BY GPU !!!\n");
    fprintf(stderr, "Please import this private key into your Tox client:\n");
    fprintf(stderr, "PRIVATE KEY (HEX): %s\n", private_key_hex);
    fprintf(stderr, "=========================================================\n");
    dbg(2, "Found private key (HEX) by GPU: %s\n", private_key_hex);

    // If you REALLY need a .dat file generated *by this specific key*,
    // you would need to implement a complex savedata constructor here
    // using libsodium to derive the public key, and then manually
    // assembling the Tox_Savedata format (version, nospam, etc.).
    // This is beyond the scope of a simple vanity generator.
    // The recommended way is to import the HEX key.
}

void *thread_find_address(void *data)
{
    char *wanted_address_string = (char *) data;
    // pthread_t id = pthread_self(); // Can be used for thread-specific logging/stats

    Tox *tox = NULL;
    struct Tox_Options options;
    uint64_t addr_per_sec_counter = 0;
    uint32_t seconds = (uint32_t)time(NULL);
    int found_local = 0; // Local flag for this thread

    while (atomic_load(&found_global) == 0) // Loop as long as global_found is not set
    {
        tox_options_default(&options);
        // We don't load savedata, so tox_new generates a new key pair
        tox = tox_new(&options, NULL);

        if (tox)
        {
            addr_per_sec_counter++;
            
            // Periodically print CPU addresses/second
            if (((uint32_t)time(NULL) - seconds) >= 10)
            {
                fprintf(stderr, "Addresses per second (CPU): %lld\n",
                    (long long)( addr_per_sec_counter / ((uint32_t)time(NULL) - seconds) ));
                seconds = (uint32_t)time(NULL);
                addr_per_sec_counter = 0;
            }
            
            found_local = check_if_found(tox, wanted_address_string);
            
            if (found_local == 1)
            {
                // If this thread found it, try to set the global flag
                // Atomically attempt to claim success for this worker
                int expected = 0;
                if (atomic_compare_exchange_strong(&found_global, &expected, 1)) {
                    fprintf(stderr, "\n** ADDRESS FOUND BY CPU THREAD! **\n");
                    dbg(2, "Address found by CPU thread!\n");
                    char tox_id_hex[TOX_ADDRESS_SIZE * 2 + 1];
                    get_my_toxid(tox, tox_id_hex);
                    char save_file_str[1000];
                    snprintf(save_file_str, sizeof(save_file_str), "toxsave_CPU_found_%s.dat", tox_id_hex);
                    update_savedata_file(tox, save_file_str);
                    tox_kill(tox);
                    tox = NULL;
                    break; // Exit loop, as this thread succeeded and set found_global
                } else {
                    // Another thread/GPU found it first. Just exit.
                    dbg(2, "CPU thread found address but another worker found it first.\n");
                    tox_kill(tox);
                    tox = NULL;
                    break;
                }
            }
            
            // If this thread didn't find it, but found_global is now set by someone else, exit.
            if (atomic_load(&found_global) != 0) {
                if (tox) {
                    tox_kill(tox);
                    tox = NULL;
                }
                break;
            }

            // Always kill Tox instance after checking to free resources
            if (tox) {
                tox_kill(tox);
                tox = NULL;
            }
        } else {
            dbg(0, "tox_new failed in CPU thread. Retrying...\n");
            // If tox_new fails, wait a bit to avoid busy-looping on errors
            yieldcpu(100);
        }
    }
    
    dbg(2, "CPU thread exiting.\n");
    return NULL;
}


int main(int argc, char *argv[])
{
    // Set up signal handler for graceful exit
    if (signal(SIGINT, sigint_handler) == SIG_ERR) {
        fprintf(stderr, "Can't catch SIGINT\n");
        return -1;
    }

    logfile = fopen(log_filename, "wb");
    if (!logfile) {
        fprintf(stderr, "Failed to open log file '%s': %s\n", log_filename, strerror(errno));
        return -1;
    }
    setvbuf(logfile, NULL, _IONBF, 0); // No buffering for log file

    int cpu_cores = 1;
    int wanted_threads = -1;
    char *wanted_address_string = NULL;
    run_mode_t run_mode = MODE_HYBRID; // Default to hybrid mode
    uint wanted_len = 0;
    uint nospam_val = 0; // Default nospam value, can be overridden by -n

    int exit_requested = 0;
    int exit_status = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        const char *value = NULL;

        if (!arg || arg[0] == '\0') {
            continue;
        }

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            exit_requested = 1;
            exit_status = 0;
            break;
        }

        if (strcmp(arg, "-v") == 0 || strcmp(arg, "--version") == 0) {
            printf("Version: %s\n", global_version_string);
            exit_requested = 1;
            exit_status = 0;
            break;
        }

        if (strncmp(arg, "--", 2) == 0) {
            const char *name = arg + 2;
            const char *eq = strchr(name, '=');
            size_t name_len = 0;
            if (eq) {
                name_len = (size_t)(eq - name);
                value = eq + 1;
                if (value && value[0] == '\0') {
                    value = NULL;
                }
            } else {
                name_len = strlen(name);
            }

#define LONG_OPT_MATCH(optname) (name_len == strlen(optname) && strncmp(name, optname, name_len) == 0)

            if (LONG_OPT_MATCH("address")) {
                if (!value) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "Option --address requires a value.\n");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    value = argv[++i];
                }
                char *dup = duplicate_uppercase_prefix(value, &wanted_len);
                if (!dup) {
                    fprintf(stderr, "Error: Invalid or too long address prefix.\n");
                    exit_requested = 1;
                    exit_status = -2;
                    break;
                }
                if (wanted_address_string) {
                    free(wanted_address_string);
                }
                wanted_address_string = dup;
                dbg(3, "Wanted Vanity Address: %s (len: %u)\n", wanted_address_string, wanted_len);
                continue;
            }

            if (LONG_OPT_MATCH("threads")) {
                if (!value) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "Option --threads requires a value.\n");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    value = argv[++i];
                }
                char *endptr = NULL;
                long parsed = strtol(value, &endptr, 10);
                if (!value || endptr == value || *endptr != '\0') {
                    fprintf(stderr, "Invalid thread count: %s\n", value ? value : "(null)");
                    exit_requested = 1;
                    exit_status = -2;
                    break;
                }
                if (parsed < 0) {
                    parsed = 0;
                }
                wanted_threads = (int)parsed;
                dbg(3, "Using %d CPU Threads\n", wanted_threads);
                continue;
            }

            if (LONG_OPT_MATCH("mode")) {
                if (!value) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "Option --mode requires a value.\n");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    value = argv[++i];
                }
                if (parse_mode_string(value, &run_mode) != 0) {
                    fprintf(stderr, "Invalid mode: %s. Use 'cpu', 'gpu', or 'hybrid'.\n", value);
                    exit_requested = 1;
                    exit_status = -2;
                    break;
                }
                dbg(3, "Run mode set to: %d\n", run_mode);
                continue;
            }

            if (LONG_OPT_MATCH("nospam")) {
                if (!value) {
                    if (i + 1 >= argc) {
                        fprintf(stderr, "Option --nospam requires a value.\n");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    value = argv[++i];
                }
                nospam_val = (uint)strtoul(value, NULL, 0);
                dbg(3, "Nospam value set to: 0x%08X (%u)\n", nospam_val, nospam_val);
                continue;
            }

            fprintf(stderr, "Unknown option: %s\n", arg);
            exit_requested = 1;
            exit_status = -2;
            break;
        }

#undef LONG_OPT_MATCH

        if (arg[0] == '-' && arg[1] != '\0') {
            char opt = arg[1];
            const char *attached = arg + 2;
            if (attached && attached[0] == '\0') {
                attached = NULL;
            }

            switch (opt) {
                case 'a': {
                    value = attached;
                    if (!value) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "Option -a requires a value.\n");
                            exit_requested = 1;
                            exit_status = -2;
                            break;
                        }
                        value = argv[++i];
                    }
                    char *dup = duplicate_uppercase_prefix(value, &wanted_len);
                    if (!dup) {
                        fprintf(stderr, "Error: Invalid or too long address prefix.\n");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    if (wanted_address_string) {
                        free(wanted_address_string);
                    }
                    wanted_address_string = dup;
                    dbg(3, "Wanted Vanity Address: %s (len: %u)\n", wanted_address_string, wanted_len);
                    break;
                }

                case 't': {
                    value = attached;
                    if (!value) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "Option -t requires a value.\n");
                            exit_requested = 1;
                            exit_status = -2;
                            break;
                        }
                        value = argv[++i];
                    }
                    char *endptr = NULL;
                    long parsed = strtol(value, &endptr, 10);
                    if (!value || endptr == value || *endptr != '\0') {
                        fprintf(stderr, "Invalid thread count: %s\n", value ? value : "(null)");
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    if (parsed < 0) {
                        parsed = 0;
                    }
                    wanted_threads = (int)parsed;
                    dbg(3, "Using %d CPU Threads\n", wanted_threads);
                    break;
                }

                case 'm': {
                    value = attached;
                    if (!value) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "Option -m requires a value.\n");
                            exit_requested = 1;
                            exit_status = -2;
                            break;
                        }
                        value = argv[++i];
                    }
                    if (parse_mode_string(value, &run_mode) != 0) {
                        fprintf(stderr, "Invalid mode: %s. Use 'cpu', 'gpu', or 'hybrid'.\n", value);
                        exit_requested = 1;
                        exit_status = -2;
                        break;
                    }
                    dbg(3, "Run mode set to: %d\n", run_mode);
                    break;
                }

                case 'n': {
                    value = attached;
                    if (!value) {
                        if (i + 1 >= argc) {
                            fprintf(stderr, "Option -n requires a value.\n");
                            exit_requested = 1;
                            exit_status = -2;
                            break;
                        }
                        value = argv[++i];
                    }
                    nospam_val = (uint)strtoul(value, NULL, 0);
                    dbg(3, "Nospam value set to: 0x%08X (%u)\n", nospam_val, nospam_val);
                    break;
                }

                default:
                    fprintf(stderr, "Unknown option: %s\n", arg);
                    exit_requested = 1;
                    exit_status = -2;
                    break;
            }

            if (exit_requested) {
                break;
            }

            continue;
        }

        fprintf(stderr, "Unexpected argument: %s\n", arg);
        exit_requested = 1;
        exit_status = -2;
        break;
    }

    if (exit_requested) {
        if (logfile) fclose(logfile);
        if (wanted_address_string) free(wanted_address_string);
        return exit_status;
    }

    cpu_cores = get_logical_cpu_count();
    dbg(9, "Detected %d processors\n", cpu_cores);

    if (wanted_threads == -1) {
        wanted_threads = cpu_cores;
    }
    // Ensure at least 1 CPU thread if CPU mode is selected and no specific thread count is given
    if (wanted_threads == 0 && (run_mode == MODE_CPU || run_mode == MODE_HYBRID)) {
        wanted_threads = 1;
        fprintf(stderr, "Warning: CPU threads set to 0, but CPU mode selected. Using 1 CPU thread.\n");
        dbg(1, "Warning: CPU threads set to 0, but CPU mode selected. Using 1 CPU thread.\n");
    }


    if (!wanted_address_string || wanted_len < 1) {
        dbg(0, "No address prefix given.\n");
        fprintf(stderr, "Error: No address prefix given. Use -a or --address.\n");
        if (logfile) fclose(logfile);
        if (wanted_address_string) free(wanted_address_string);
        return -2;
    }
    // Tox ID is 38 bytes, so 76 hex chars max
    if (wanted_len > TOX_ADDRESS_SIZE * 2) {
        dbg(0, "Address prefix too long.\n");
        fprintf(stderr, "Error: Address prefix too long (max %d hex characters).\n", TOX_ADDRESS_SIZE * 2);
        if (logfile) fclose(logfile);
        if (wanted_address_string) free(wanted_address_string);
        return -2;
    }

    // Determine initial RNG nonce for GPU based on current time and PID
    // This helps ensure different starting points across multiple runs
    ulong initial_rng_nonce = (ulong)time(NULL) ^ (ulong)getpid();
    if (initial_rng_nonce == 0) initial_rng_nonce = 1; // Ensure non-zero seed

    printf("Starting search for Tox ID with prefix: %s (Mode: %s, CPU Threads: %d, Nospam: 0x%08X)\n",
           wanted_address_string,
           run_mode == MODE_CPU ? "CPU" : (run_mode == MODE_GPU ? "GPU" : "Hybrid"),
           wanted_threads, nospam_val);
    fprintf(stderr, "Searching for Tox ID with prefix: %s\n", wanted_address_string);
    dbg(2, "Starting search for Tox ID with prefix: %s\n", wanted_address_string);

    // --- Launch GPU-part ---
    if (run_mode == MODE_GPU || run_mode == MODE_HYBRID) {
        if (setup_opencl(wanted_address_string, wanted_len, nospam_val, initial_rng_nonce) != 0) {
            fprintf(stderr, "Failed to initialize OpenCL. Check your drivers and OpenCL SDK.\n");
            cleanup_opencl();
            if (wanted_address_string) free(wanted_address_string);
            if (logfile) fclose(logfile);
            return -1;
        }
        printf("Starting GPU search on %s...\n", device_name_str);
        dbg(2, "Starting GPU search on %s...\n", device_name_str);
        if (run_gpu_search() != 0) {
            fprintf(stderr, "Failed to launch initial GPU kernel.\n");
            dbg(0, "Failed to launch initial GPU kernel.\n");
            cleanup_opencl();
            if (wanted_address_string) free(wanted_address_string);
            if (logfile) fclose(logfile);
            return -1;
        }
    }

    // --- Launch CPU-part ---
    portable_thread_t *tid = NULL; // Declared outside, initialized here
    if (run_mode == MODE_CPU || run_mode == MODE_HYBRID) {
        if (wanted_threads > 0) {
            tid = calloc((size_t)wanted_threads, sizeof(*tid));
            if (!tid) {
                fprintf(stderr, "Failed to allocate memory for CPU threads.\n");
                cleanup_opencl();
                if (wanted_address_string) free(wanted_address_string);
                if (logfile) fclose(logfile);
                return -1;
            }
            printf("Starting CPU search on %d threads...\n", wanted_threads);
            dbg(2, "Starting CPU search on %d threads...\n", wanted_threads);
            for (int c = 0; c < wanted_threads; c++) {
                int create_err = portable_thread_create(&(tid[c]), thread_find_address, (void *)wanted_address_string);
                if (create_err != 0) {
#if defined(_WIN32)
                    dbg(0, "Thread %d create failed (err=%d)\n", c, create_err);
                    fprintf(stderr, "Error: Thread %d creation failed with error %d. Aborting CPU search for remaining threads.\n", c, create_err);
#else
                    dbg(0, "Thread %d create failed: %s\n", c, strerror(create_err));
                    fprintf(stderr, "Error: Thread %d creation failed (%s). Aborting CPU search for remaining threads.\n", c, strerror(create_err));
#endif
                    wanted_threads = c; // Update count of successfully launched threads
                    break;
                }
                dbg(2, "Thread %d successfully created\n", c);
            }
        } else {
             fprintf(stderr, "Warning: Number of CPU threads set to 0. CPU search will not run.\n");
             dbg(1, "Warning: Number of CPU threads set to 0. CPU search will not run.\n");
        }
    }


    // --- Main waiting loop ---
    fprintf(stderr, "Searching...\n");
    while (atomic_load(&found_global) == 0) {
        // If GPU is active, check its flag
        if (atomic_load(&found_global) == 0 && (run_mode == MODE_GPU || run_mode == MODE_HYBRID)) {
            uint gpu_found_flag = 0;
            // Read flag value from GPU memory to CPU memory
            cl_int err = clEnqueueReadBuffer(command_queue, found_flag_buf, CL_TRUE, 0, sizeof(uint), &gpu_found_flag, 0, NULL, NULL);
            if (err != CL_SUCCESS) {
                fprintf(stderr, "Error reading found_flag_buf from GPU: %s\n", clGetErrorString(err));
                dbg(0, "Error reading found_flag_buf from GPU: %s\n", clGetErrorString(err));
                // If we can't read the flag, something is wrong, better stop.
                atomic_store(&found_global, 1); // Force exit
                break;
            }

            if (gpu_found_flag) {
                // Atomically set found_global to 1. Only the first one to do this wins.
                int expected = 0;
                if (atomic_compare_exchange_strong(&found_global, &expected, 1)) {
                    // We were the first to find, so retrieve and save the key
                    err = clEnqueueReadBuffer(command_queue, found_key_buf, CL_TRUE, 0, 32, gpu_found_private_key, 0, NULL, NULL);
                    if (err == CL_SUCCESS) {
                        save_tox_profile_from_private_key(gpu_found_private_key);
                    } else {
                        fprintf(stderr, "Error reading found_key_buf from GPU: %s\n", clGetErrorString(err));
                        dbg(0, "Error reading found_key_buf from GPU: %s\n", clGetErrorString(err));
                    }
                } else {
                    dbg(2, "GPU found address but another worker (CPU) set the flag first.\n");
                }
                break; // Exit loop
            } else if (atomic_load(&found_global) == 0) {
                if (run_gpu_search() != 0) {
                    fprintf(stderr, "Failed to relaunch GPU search. Stopping GPU worker.\n");
                    dbg(0, "Failed to relaunch GPU search.\n");
                    atomic_store(&found_global, 1);
                    break;
                }
            }
        }

        if (atomic_load(&found_global) == 0) {
            yieldcpu(10); // Small delay to prevent busy-waiting without stalling GPU relaunches
        }
    }

    // --- Cleanup and exit ---
    printf("\nAddress found or stopped. Cleaning up...\n");
    dbg(2, "Address found or stopped. Cleaning up...\n");

    // Wait for CPU threads to finish (if they were launched)
    if (tid) {
        for (int c = 0; c < wanted_threads; c++) {
            int join_err = portable_thread_join(tid[c]);
            if (join_err == 0) {
                dbg(9, "CPU thread %d joined.\n", c);
            } else {
#if defined(_WIN32)
                dbg(1, "Failed to join CPU thread %d (err=%d)\n", c, join_err);
#else
                dbg(1, "Failed to join CPU thread %d: %s\n", c, strerror(join_err));
#endif
            }
        }
        free(tid);
    }

    // Release OpenCL resources
    if (run_mode == MODE_GPU || run_mode == MODE_HYBRID) {
        cleanup_opencl();
    }

    if (wanted_address_string) {
        free(wanted_address_string);
    }

    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }

    printf("Exiting.\n");
    return 0;
}