/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Laboratorio 3:   Busqueda secuencial MEJORADA de una clave AES-128
 * 
 * Autores:
 *  - Angie Nadissa Vela López, 23764
 *  - Roberto Camposeco Torres, 23968
 *  - Javier Alexander Linares Chang, 231135
 * 
 * Descripcion: un unico proceso prueba claves candidatas en orden.
 *
 * Mejoras respecto a la version original:
 *   1. (Javier)  La clave "debilitada" se documenta y se compara contra
 *                el espacio completo de AES-128 (2^128).
 *   2. (Javier)  AES-128-CBC con IV aleatorio en lugar de ECB.
 *   3. (Nadissa) Clave secreta, tamano del rango y mensaje por argumentos.
 *   4. (Nadissa) Filtro rapido con un prefijo conocido; confirmacion
 *                completa solo cuando una candidata pasa el filtro.
 *   5. (Nadissa) Estadisticas: claves probadas, claves/s y % de 2^128.
 *   6. (Roberto) El contexto EVP se prepara una vez; en el ciclo solo
 *                se cambia la clave.
 *   7. (Roberto) Borrado seguro de claves en memoria y liberacion de
 *                recursos ante cualquier error.
 *
 * Compilacion:
 *   gcc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_secuencial_mejorado.c \
 *       -o busqueda_clave_aes_secuencial_mejorado -lcrypto
 * Uso:
 *   ./busqueda_clave_aes_secuencial_mejorado [clave] [bits_rango] [mensaje]
 *   Por defecto: clave=12345, bits_rango=20, mensaje="Puedes lograrlo!"
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
#define MAX_MSG_LEN    256
#define PREFIX_LEN     8     /* bytes conocidos usados como filtro rapido */
#define DEFAULT_SECRET UINT64_C(12345)
#define DEFAULT_BITS   20
#define DEFAULT_MSG    "Puedes lograrlo!"

static EVP_CIPHER_CTX *g_fast = NULL;  /* descifra 1 bloque, sin padding */
static EVP_CIPHER_CTX *g_full = NULL;  /* confirmacion completa, con padding */

/* Libera recursos y termina con error. */
static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    exit(EXIT_FAILURE);
}

/*
 * Clave AES-128 "debilitada a proposito": 8 bytes en cero y la candidata
 * en los 8 bytes bajos. Solo para el ejercicio: NO es una clave segura.
 */
static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);
    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)((candidate >> (8 * i)) & 0xFF);
    }
}

/* Cifra el mensaje completo con AES-128-CBC y padding PKCS#7. */
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

/* Filtro rapido: descifra solo el primer bloque y compara el prefijo. */
static int quick_check(uint64_t candidate, const unsigned char *iv,
                       const unsigned char *cipher,
                       const unsigned char *msg)
{
    unsigned char key[16], block[BLOCK_LEN + EVP_MAX_BLOCK_LENGTH];
    int n = 0;

    make_key(candidate, key);
    /* Solo cambia la clave: el cifrador ya esta configurado. */
    if (EVP_DecryptInit_ex(g_fast, NULL, NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(g_fast, 0) != 1 ||
        EVP_DecryptUpdate(g_fast, block, &n, cipher, BLOCK_LEN) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        fail("Error en el filtro rapido.");
    }
    OPENSSL_cleanse(key, sizeof key);
    return memcmp(block, msg, PREFIX_LEN) == 0;
}

/* Confirmacion completa: descifra todo y compara con el mensaje. */
static int full_check(uint64_t candidate, const unsigned char *iv,
                      const unsigned char *cipher, int cipher_len,
                      const unsigned char *msg, int msg_len,
                      unsigned char *plain)
{
    unsigned char key[16];
    int n = 0, f = 0;

    make_key(candidate, key);
    if (EVP_DecryptInit_ex(g_full, NULL, NULL, key, iv) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        fail("Error al inicializar la confirmacion.");
    }
    OPENSSL_cleanse(key, sizeof key);
    if (EVP_DecryptUpdate(g_full, plain, &n, cipher, cipher_len) != 1) {
        return 0;
    }
    if (EVP_DecryptFinal_ex(g_full, plain + n, &f) != 1) {
        return 0;               /* relleno invalido: clave incorrecta */
    }
    return (n + f == msg_len) && memcmp(plain, msg, (size_t)msg_len) == 0;
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

int main(int argc, char **argv)
{
    uint64_t secret = DEFAULT_SECRET;
    int bits = DEFAULT_BITS;
    const char *text = DEFAULT_MSG;

    if (argc > 1) secret = strtoull(argv[1], NULL, 10);
    if (argc > 2) bits = atoi(argv[2]);
    if (argc > 3) text = argv[3];

    size_t len = strlen(text);
    if (bits < 1 || bits > 40 || len < PREFIX_LEN || len > MAX_MSG_LEN) {
        fprintf(stderr, "Uso: %s [clave] [bits_rango 1..40] "
                "[mensaje de %d a %d bytes]\n", argv[0], PREFIX_LEN, MAX_MSG_LEN);
        return EXIT_FAILURE;
    }
    uint64_t total = UINT64_C(1) << bits;
    if (secret >= total) {
        fprintf(stderr, "La clave secreta debe ser menor que 2^%d.\n", bits);
        return EXIT_FAILURE;
    }

    const unsigned char *msg = (const unsigned char *)text;
    int msg_len = (int)len;

    unsigned char iv[BLOCK_LEN];
    unsigned char cipher[MAX_MSG_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char plain[MAX_MSG_LEN + EVP_MAX_BLOCK_LENGTH] = {0};

    /* IV aleatorio: el mismo mensaje no produce el mismo cifrado. */
    if (RAND_bytes(iv, sizeof iv) != 1) fail("Error al generar el IV.");
    int cipher_len = encrypt_message(secret, iv, msg, msg_len, cipher);

    /* Contextos preparados una sola vez (mejora 6). */
    g_fast = EVP_CIPHER_CTX_new();
    g_full = EVP_CIPHER_CTX_new();
    unsigned char zero[16] = {0};
    if (g_fast == NULL || g_full == NULL ||
        EVP_DecryptInit_ex(g_fast, EVP_aes_128_cbc(), NULL, zero, iv) != 1 ||
        EVP_DecryptInit_ex(g_full, EVP_aes_128_cbc(), NULL, zero, iv) != 1) {
        fail("Error al preparar los contextos de OpenSSL.");
    }

    printf("Rango: 2^%d = %" PRIu64 " candidatas | mensaje: %d bytes\n",
           bits, total, msg_len);

    uint64_t found = UINT64_MAX, tested = 0;
    double start = get_time();

    for (uint64_t k = 0; k < total; k++) {
        tested++;
        if (quick_check(k, iv, cipher, msg) &&
            full_check(k, iv, cipher, cipher_len, msg, msg_len, plain)) {
            found = k;
            break;
        }
    }

    double elapsed = get_time() - start;

    if (found != UINT64_MAX) {
        printf("Clave encontrada: %" PRIu64 "\n", found);
        printf("Mensaje: %.*s\n", msg_len, plain);
    } else {
        printf("No se encontro la clave.\n");
    }

    printf("Ejecucion: secuencial mejorado\n");
    printf("Tiempo: %.6f segundos\n", elapsed);
    printf("Claves probadas: %" PRIu64 "\n", tested);
    printf("Claves por segundo: %.0f\n", elapsed > 0 ? tested / elapsed : 0.0);
    printf("Fraccion de AES-128 explorada: %.3e %% (2^%d de 2^128)\n",
           (double)tested / 3.402823669209385e38 * 100.0, bits);

    OPENSSL_cleanse(plain, sizeof plain);
    OPENSSL_cleanse(cipher, sizeof cipher);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    return EXIT_SUCCESS;
}
