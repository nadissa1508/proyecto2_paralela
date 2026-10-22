/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Proyecto 2:  Busqueda SECUENCIAL de una clave AES-128 (linea base)
 *
 * Autores:
 *  - Angie Nadissa Vela Lopez, 23764
 *  - Roberto Camposeco Torres, 23968
 *  - Javier Alexander Linares Chang, 231135
 *
 * Cambios respecto a busqueda_clave_aes_secuencial_v2.c:
 *   1. El mensaje se lee de un archivo .txt; la clave es parametro.
 *   2. El filtro busca la frase "es una prueba de" en el texto descifrado
 *      (cruza los bloques 1 y 2 de AES-CBC) en lugar de un prefijo.
 *   3. El rango admite hasta 56 bits.
 * Se mantiene la interfaz EVP del Lab 3 (contextos reutilizados).
 *
 * Compilacion:
 *   gcc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_secuencial_v3.c \
 *       -o busqueda_clave_aes_secuencial_v3 -lcrypto
 * Uso:
 *   ./busqueda_clave_aes_secuencial_v3 <archivo.txt> <clave|aleatoria>
 *                                      [bits=56] [-f]
 *   -f  permite una clave fuera del rango (prueba de "sin clave")
 *----------------------------------------------------------------------*/

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BLOCK_LEN      16
#define MAX_MSG_LEN    4096
#define PHRASE_LEN     16
#define MAX_BITS       56
#define DEFAULT_BITS   56
#define NOT_FOUND      UINT64_MAX

static const unsigned char PHRASE[PHRASE_LEN + 1] = "es una prueba de";

static EVP_CIPHER_CTX *g_fast = NULL;  /* descifra 2 bloques, sin padding */
static EVP_CIPHER_CTX *g_full = NULL;  /* confirmacion completa, con padding */

static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    exit(EXIT_FAILURE);
}

/* Clave AES-128 debilitada a proposito: 8 bytes en cero + candidata (BE). */
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

/* Descifra con una clave conocida. Devuelve la longitud o -1. */
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

static double get_time(void)
{
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t) != 0) {
        perror("Error al consultar el reloj");
        exit(EXIT_FAILURE);
    }
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
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
        fprintf(stderr, "Uso: %s <archivo.txt> <clave|aleatoria> [bits=%d] [-f]\n"
                "  El mensaje debe contener \"%s\" en los primeros %d bytes.\n",
                argv[0], DEFAULT_BITS, PHRASE, BLOCK_LEN);
        return EXIT_FAILURE;
    }
    const uint64_t total = UINT64_C(1) << bits;

    unsigned char msg[MAX_MSG_LEN + 1] = {0};
    int msg_len = read_file(path, msg, MAX_MSG_LEN);
    if (msg_len < 0) {
        fprintf(stderr, "No se pudo leer '%s' (o excede %d bytes).\n", path, MAX_MSG_LEN);
        return EXIT_FAILURE;
    }
    int off = find_phrase(msg, msg_len);
    if (off < 0 || off >= BLOCK_LEN) {
        fprintf(stderr, "El mensaje debe contener \"%s\" empezando en los primeros %d bytes.\n",
                PHRASE, BLOCK_LEN);
        return EXIT_FAILURE;
    }

    uint64_t secret;
    if (strcmp(keyarg, "aleatoria") == 0) {
        if (RAND_bytes((unsigned char *)&secret, sizeof secret) != 1)
            fail("Error al generar la clave aleatoria.");
        secret &= (total - 1);
    } else {
        char *end = NULL;
        secret = strtoull(keyarg, &end, 10);
        if (end == keyarg || *end != '\0') {
            fprintf(stderr, "Clave invalida: '%s'.\n", keyarg);
            return EXIT_FAILURE;
        }
    }
    if (!outside && secret >= total) {
        fprintf(stderr, "La clave debe ser menor que 2^%d (use -f para forzar).\n", bits);
        return EXIT_FAILURE;
    }

    unsigned char iv[BLOCK_LEN];
    unsigned char cipher[MAX_MSG_LEN + 2 * BLOCK_LEN];
    unsigned char plain[MAX_MSG_LEN + 2 * BLOCK_LEN] = {0};

    if (RAND_bytes(iv, sizeof iv) != 1) fail("Error al generar el IV.");
    int cipher_len = encrypt_message(secret, iv, msg, msg_len, cipher);

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

    g_fast = EVP_CIPHER_CTX_new();
    g_full = EVP_CIPHER_CTX_new();
    unsigned char zero[16] = {0};
    if (g_fast == NULL || g_full == NULL ||
        EVP_DecryptInit_ex(g_fast, EVP_aes_128_cbc(), NULL, zero, iv) != 1 ||
        EVP_DecryptInit_ex(g_full, EVP_aes_128_cbc(), NULL, zero, iv) != 1) {
        fail("Error al preparar los contextos de OpenSSL.");
    }

    printf("Rango: 2^%d = %" PRIu64 " candidatas\n", bits, total);

    uint64_t found = NOT_FOUND, tested = 0;
    int plain_len = 0;
    double start = get_time();

    for (uint64_t k = 0; k < total; k++) {
        tested++;
        if (quick_check(k, iv, cipher) &&
            full_check(k, iv, cipher, cipher_len, plain, &plain_len)) {
            found = k;
            break;
        }
    }

    double elapsed = get_time() - start;

    printf("=== Resultado ===\n");
    if (found != NOT_FOUND) {
        make_key(found, key128);
        printf("Clave encontrada: %" PRIu64 "\n", found);
        printf("Clave (128 bits): "); print_hex(key128, 16);
        printf("Mensaje: %.*s\n", plain_len, plain);
        printf("Coincide con la clave original: %s\n", found == secret ? "SI" : "NO");
    } else {
        printf("No se encontro la clave.\n");
    }
    printf("Ejecucion: secuencial\n");
    printf("Tiempo total: %.6f segundos\n", elapsed);
    printf("Candidatas probadas (total): %" PRIu64 "\n", tested);
    printf("Claves por segundo: %.0f\n", elapsed > 0 ? (double)tested / elapsed : 0.0);

    OPENSSL_cleanse(plain, sizeof plain);
    OPENSSL_cleanse(cipher, sizeof cipher);
    OPENSSL_cleanse(msg, sizeof msg);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    return EXIT_SUCCESS;
}
