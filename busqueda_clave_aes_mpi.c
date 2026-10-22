/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Proyecto 2:  Busqueda paralela (Open MPI) - ESTRATEGIA BASE
 *              (distribucion ciclica por bloques + MPI_Allreduce por ronda)
 *
 * Autores:
 *  - Angie Nadissa Vela Lopez, 23764
 *  - Roberto Camposeco Torres, 23968
 *  - Javier Alexander Linares Chang, 231135
 *
 * Distribucion (igual que el Lab 3): el rango [0, 2^bits) se divide en
 * bloques de CHUNK candidatas; en la ronda r el proceso i prueba el
 * bloque r*size + i. Al terminar cada ronda todos ejecutan MPI_Allreduce
 * (MIN) con la menor clave encontrada.
 *
 * Cambios respecto a busqueda_clave_aes_mpi.c:
 *   1. El mensaje se lee de un archivo .txt; la clave es parametro.
 *   2. El filtro busca la frase "es una prueba de" (cruza los bloques 1 y
 *      2 de AES-CBC) en lugar de un prefijo.
 *   3. El rango admite hasta 56 bits.
 *   4. Estadisticas por proceso (candidatas, tiempo, claves/s).
 * Se mantiene la interfaz EVP del Lab 3.
 *
 * Compilacion:
 *   mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi_v3_base.c \
 *         -o busqueda_clave_aes_mpi_v3_base -lcrypto
 * Uso:
 *   mpirun -np 4 ./busqueda_clave_aes_mpi_v3_base <archivo.txt>
 *                 <clave|aleatoria> [bits=56] [-f]
 *   -f  permite una clave fuera del rango (prueba de "sin clave")
 *----------------------------------------------------------------------*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <mpi.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BLOCK_LEN      16
#define MAX_MSG_LEN    4096
#define PHRASE_LEN     16
#define MAX_BITS       56
#define DEFAULT_BITS   56
#define CHUNK          UINT64_C(4096)
#define NOT_FOUND      UINT64_MAX

static const unsigned char PHRASE[PHRASE_LEN + 1] = "es una prueba de";

static EVP_CIPHER_CTX *g_fast = NULL;
static EVP_CIPHER_CTX *g_full = NULL;

static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    MPI_Abort(MPI_COMM_WORLD, EXIT_FAILURE);
    exit(EXIT_FAILURE);
}

static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);
    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)((candidate >> (8 * i)) & 0xFF);
    }
}

static int find_phrase(const unsigned char *buf, int n)
{
    for (int i = 0; i + PHRASE_LEN <= n; i++) {
        if (buf[i] == PHRASE[0] && memcmp(buf + i, PHRASE, PHRASE_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

static int encrypt_message(uint64_t secret, const unsigned char *iv,
                           const unsigned char *msg, int msg_len,
                           unsigned char *out)
{
    unsigned char key[16];
    int n = 0, f = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    make_key(secret, key);
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 ||
        EVP_EncryptUpdate(ctx, out, &n, msg, msg_len) != 1 ||
        EVP_EncryptFinal_ex(ctx, out + n, &f) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        EVP_CIPHER_CTX_free(ctx);
        fail("Error al cifrar el mensaje.");
    }
    OPENSSL_cleanse(key, sizeof key);
    EVP_CIPHER_CTX_free(ctx);
    return n + f;
}

static int decrypt_message(uint64_t secret, const unsigned char *iv,
                           const unsigned char *cipher, int cipher_len,
                           unsigned char *out)
{
    unsigned char key[16];
    int n = 0, f = 0, ok;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    make_key(secret, key);
    ok = ctx != NULL &&
         EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) == 1 &&
         EVP_DecryptUpdate(ctx, out, &n, cipher, cipher_len) == 1 &&
         EVP_DecryptFinal_ex(ctx, out + n, &f) == 1;
    OPENSSL_cleanse(key, sizeof key);
    EVP_CIPHER_CTX_free(ctx);
    return ok ? n + f : -1;
}

/* Filtro rapido: descifra los 2 primeros bloques y busca la frase. */
static int quick_check(uint64_t candidate, const unsigned char *iv,
                       const unsigned char *cipher)
{
    unsigned char key[16], buf[2 * BLOCK_LEN + EVP_MAX_BLOCK_LENGTH];
    int n = 0;

    make_key(candidate, key);
    if (EVP_DecryptInit_ex(g_fast, NULL, NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(g_fast, 0) != 1 ||
        EVP_DecryptUpdate(g_fast, buf, &n, cipher, 2 * BLOCK_LEN) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        fail("Error en el filtro rapido.");
    }
    OPENSSL_cleanse(key, sizeof key);
    return find_phrase(buf, n) >= 0;
}

/* Confirmacion: descifra todo, valida relleno y busca la frase. */
static int full_check(uint64_t candidate, const unsigned char *iv,
                      const unsigned char *cipher, int cipher_len,
                      unsigned char *plain, int *plain_len)
{
    unsigned char key[16];
    int n = 0, f = 0;

    make_key(candidate, key);
    if (EVP_DecryptInit_ex(g_full, NULL, NULL, key, iv) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        fail("Error al inicializar la confirmacion.");
    }
    OPENSSL_cleanse(key, sizeof key);
    if (EVP_DecryptUpdate(g_full, plain, &n, cipher, cipher_len) != 1) return 0;
    if (EVP_DecryptFinal_ex(g_full, plain + n, &f) != 1) return 0;
    if (find_phrase(plain, n + f) < 0) return 0;
    *plain_len = n + f;
    return 1;
}

static int read_file(const char *path, unsigned char *buf, int cap)
{
    FILE *f = fopen(path, "rb");
    if (f == NULL) return -1;
    size_t n = fread(buf, 1, (size_t)cap + 1, f);
    fclose(f);
    if (n > (size_t)cap) return -2;
    while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r')) n--;
    return (int)n;
}

static void print_hex(const unsigned char *b, int n)
{
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
    printf("\n");
}

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);
    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    const char *path = NULL, *keyarg = NULL;
    int bits = DEFAULT_BITS, outside = 0, npos = 0, argerr = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-f") == 0) outside = 1;
        else if (npos == 0) { path = argv[i]; npos++; }
        else if (npos == 1) { keyarg = argv[i]; npos++; }
        else if (npos == 2) { bits = atoi(argv[i]); npos++; }
        else argerr = 1;
    }
    if (path == NULL || keyarg == NULL || argerr || bits < 1 || bits > MAX_BITS) {
        if (rank == 0)
            fprintf(stderr, "Uso: mpirun -np N %s <archivo.txt> <clave|aleatoria> "
                    "[bits=%d] [-f]\n  El mensaje debe contener \"%s\" en los "
                    "primeros %d bytes.\n", argv[0], DEFAULT_BITS, PHRASE, BLOCK_LEN);
        MPI_Finalize();
        return EXIT_FAILURE;
    }
    const uint64_t total = UINT64_C(1) << bits;

    unsigned char iv[BLOCK_LEN];
    unsigned char cipher[MAX_MSG_LEN + 2 * BLOCK_LEN];
    unsigned char plain[MAX_MSG_LEN + 2 * BLOCK_LEN] = {0};
    unsigned char msg[MAX_MSG_LEN + 1] = {0};
    int cipher_len = 0, msg_len = 0, status = 0, plain_len = 0;
    uint64_t secret = 0;

    /* El proceso 0 lee el archivo, cifra y comparte el resultado. */
    if (rank == 0) {
        msg_len = read_file(path, msg, MAX_MSG_LEN);
        if (msg_len < 0) {
            fprintf(stderr, "No se pudo leer '%s' (o excede %d bytes).\n", path, MAX_MSG_LEN);
            status = 1;
        } else {
            int off = find_phrase(msg, msg_len);
            if (off < 0 || off >= BLOCK_LEN) {
                fprintf(stderr, "El mensaje debe contener \"%s\" empezando en los "
                        "primeros %d bytes.\n", PHRASE, BLOCK_LEN);
                status = 1;
            }
        }
        if (!status) {
            if (strcmp(keyarg, "aleatoria") == 0) {
                if (RAND_bytes((unsigned char *)&secret, sizeof secret) != 1)
                    fail("Error al generar la clave aleatoria.");
                secret &= (total - 1);
            } else {
                char *end = NULL;
                secret = strtoull(keyarg, &end, 10);
                if (end == keyarg || *end != '\0') {
                    fprintf(stderr, "Clave invalida: '%s'.\n", keyarg);
                    status = 1;
                }
            }
        }
        if (!status && !outside && secret >= total) {
            fprintf(stderr, "La clave debe ser menor que 2^%d (use -f para forzar).\n", bits);
            status = 1;
        }
        if (!status) {
            if (RAND_bytes(iv, sizeof iv) != 1) fail("Error al generar el IV.");
            cipher_len = encrypt_message(secret, iv, msg, msg_len, cipher);

            unsigned char key128[16];
            make_key(secret, key128);
            printf("=== Cifrado AES-128-CBC ===\n");
            printf("Archivo:          %s (%d bytes)\n", path, msg_len);
            printf("Texto original:   %.*s\n", msg_len, msg);
            printf("Clave (decimal):  %" PRIu64 "\n", secret);
            printf("Clave (128 bits): "); print_hex(key128, 16);
            printf("IV:               "); print_hex(iv, BLOCK_LEN);
            printf("Texto cifrado:    "); print_hex(cipher, cipher_len);
            int rl = decrypt_message(secret, iv, cipher, cipher_len, plain);
            printf("Texto recuperado: ");
            if (rl >= 0) printf("%.*s\n", rl, plain); else printf("(error)\n");
            printf("Descifrado coincide con el original: %s\n\n",
                   (rl == msg_len && memcmp(plain, msg, (size_t)msg_len) == 0) ? "SI" : "NO");
            memset(plain, 0, sizeof plain);
        }
    }
    MPI_Bcast(&status, 1, MPI_INT, 0, MPI_COMM_WORLD);
    if (status) {
        MPI_Finalize();
        return EXIT_FAILURE;
    }
    MPI_Bcast(iv, BLOCK_LEN, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);
    MPI_Bcast(&cipher_len, 1, MPI_INT, 0, MPI_COMM_WORLD);
    MPI_Bcast(cipher, cipher_len, MPI_UNSIGNED_CHAR, 0, MPI_COMM_WORLD);

    g_fast = EVP_CIPHER_CTX_new();
    g_full = EVP_CIPHER_CTX_new();
    unsigned char zero[16] = {0};
    if (g_fast == NULL || g_full == NULL ||
        EVP_DecryptInit_ex(g_fast, EVP_aes_128_cbc(), NULL, zero, iv) != 1 ||
        EVP_DecryptInit_ex(g_full, EVP_aes_128_cbc(), NULL, zero, iv) != 1) {
        fail("Error al preparar los contextos de OpenSSL.");
    }

    uint64_t num_chunks = (total + CHUNK - 1) / CHUNK;
    uint64_t rounds = (num_chunks + (uint64_t)size - 1) / (uint64_t)size;

    uint64_t found = NOT_FOUND, global_found = NOT_FOUND, tested = 0;

    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    for (uint64_t r = 0; r < rounds && global_found == NOT_FOUND; r++) {
        uint64_t chunk = r * (uint64_t)size + (uint64_t)rank;

        if (chunk < num_chunks) {
            uint64_t lo = chunk * CHUNK;
            uint64_t hi = lo + CHUNK;
            if (hi > total) hi = total;

            for (uint64_t k = lo; k < hi; k++) {
                tested++;
                if (quick_check(k, iv, cipher) &&
                    full_check(k, iv, cipher, cipher_len, plain, &plain_len)) {
                    found = k;
                    break;
                }
            }
        }
        /* Todos saben si alguien encontro la clave (la menor). */
        MPI_Allreduce(&found, &global_found, 1, MPI_UINT64_T, MPI_MIN,
                      MPI_COMM_WORLD);
    }

    double elapsed = MPI_Wtime() - start;

    /* ---- Estadisticas por proceso ---- */
    uint64_t *g_tested = NULL;
    double *g_time = NULL;
    int *g_owner = NULL;
    int owner = (found != NOT_FOUND && found == global_found);
    if (rank == 0) {
        g_tested = malloc((size_t)size * sizeof *g_tested);
        g_time = malloc((size_t)size * sizeof *g_time);
        g_owner = malloc((size_t)size * sizeof *g_owner);
    }
    MPI_Gather(&tested, 1, MPI_UINT64_T, g_tested, 1, MPI_UINT64_T, 0, MPI_COMM_WORLD);
    MPI_Gather(&elapsed, 1, MPI_DOUBLE, g_time, 1, MPI_DOUBLE, 0, MPI_COMM_WORLD);
    MPI_Gather(&owner, 1, MPI_INT, g_owner, 1, MPI_INT, 0, MPI_COMM_WORLD);

    if (rank == 0) {
        printf("=== Resultado (rango 2^%d = %" PRIu64 ") ===\n", bits, total);
        if (global_found != NOT_FOUND) {
            unsigned char key128[16];
            make_key(global_found, key128);
            printf("Clave encontrada: %" PRIu64 "\n", global_found);
            printf("Clave (128 bits): "); print_hex(key128, 16);
            if (quick_check(global_found, iv, cipher) &&
                full_check(global_found, iv, cipher, cipher_len, plain, &plain_len))
                printf("Mensaje: %.*s\n", plain_len, plain);
            printf("Coincide con la clave original: %s\n",
                   global_found == secret ? "SI" : "NO");
        } else {
            printf("No se encontro la clave.\n");
        }

        double tmax = 0.0;
        uint64_t ttot = 0;
        printf("\n%-8s %-18s %-12s %-14s\n", "proceso", "candidatas", "tiempo (s)", "claves/s");
        for (int r = 0; r < size; r++) {
            printf("%-8d %-18" PRIu64 " %-12.6f %-14.0f%s\n", r, g_tested[r], g_time[r],
                   g_time[r] > 0 ? (double)g_tested[r] / g_time[r] : 0.0,
                   g_owner[r] ? "  <- hallo la clave" : "");
            if (g_time[r] > tmax) tmax = g_time[r];
            ttot += g_tested[r];
        }
        printf("\nEjecucion: paralela base (Open MPI, %d procesos)\n", size);
        printf("Tiempo total (max entre procesos): %.6f segundos\n", tmax);
        printf("Candidatas probadas (total): %" PRIu64 "\n", ttot);
        printf("Claves por segundo (agregado): %.0f\n", tmax > 0 ? (double)ttot / tmax : 0.0);
        free(g_tested); free(g_time); free(g_owner);
    }

    OPENSSL_cleanse(plain, sizeof plain);
    OPENSSL_cleanse(cipher, sizeof cipher);
    OPENSSL_cleanse(msg, sizeof msg);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
