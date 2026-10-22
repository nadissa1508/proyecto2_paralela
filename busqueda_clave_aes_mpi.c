/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3169 - Computacion Paralela y Distribuida
 * Laboratorio 3:   Busqueda paralela (Open MPI) de una clave AES-128
 * 
 * Autores:
 *  - Angie Nadissa Vela López, 23764
 *  - Roberto Camposeco Torres, 23968
 *  - Javier Alexander Linares Chang, 231135

 * Distribucion del trabajo:
 *   El rango [0, 2^bits) se divide en bloques de CHUNK candidatas.
 *   En la ronda r, el proceso i prueba el bloque numero r*size + i.
 *   Asi todos los bloques se asignan exactamente a un proceso, y el
 *   trabajo queda balanceado aunque la clave este al inicio o al final.
 *
 * Finalizacion coordinada:
 *   Al terminar cada ronda todos los procesos ejecutan MPI_Allreduce
 *   (MIN) con la menor clave encontrada. Si alguien la encontro, todos
 *   detienen la busqueda; si no, continuan hasta agotar el rango.
 *
 * Compilacion:
 *   mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi.c \
 *         -o busqueda_clave_aes_mpi -lcrypto
 * Ejecucion:
 *   mpirun -np 4 ./busqueda_clave_aes_mpi [clave] [bits_rango] [mensaje]
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
#define MAX_MSG_LEN    256
#define PREFIX_LEN     8
#define CHUNK          UINT64_C(4096)
#define DEFAULT_SECRET UINT64_C(12345)
#define DEFAULT_BITS   20
#define DEFAULT_MSG    "Puedes lograrlo!"

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

/* Clave AES-128 debilitada a proposito (solo para el ejercicio). */
static void make_key(uint64_t candidate, unsigned char key[16])
{
    memset(key, 0, 16);
    for (int i = 0; i < 8; i++) {
        key[15 - i] = (unsigned char)((candidate >> (8 * i)) & 0xFF);
    }
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

static int quick_check(uint64_t candidate, const unsigned char *iv,
                       const unsigned char *cipher,
                       const unsigned char *msg)
{
    unsigned char key[16], block[BLOCK_LEN + EVP_MAX_BLOCK_LENGTH];
    int n = 0;

    make_key(candidate, key);
    if (EVP_DecryptInit_ex(g_fast, NULL, NULL, key, iv) != 1 ||
        EVP_CIPHER_CTX_set_padding(g_fast, 0) != 1 ||
        EVP_DecryptUpdate(g_fast, block, &n, cipher, BLOCK_LEN) != 1) {
        OPENSSL_cleanse(key, sizeof key);
        fail("Error en el filtro rapido.");
    }
    OPENSSL_cleanse(key, sizeof key);
    return memcmp(block, msg, PREFIX_LEN) == 0;
}

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
        return 0;
    }
    return (n + f == msg_len) && memcmp(plain, msg, (size_t)msg_len) == 0;
}

int main(int argc, char **argv)
{
    MPI_Init(&argc, &argv);

    int rank, size;
    MPI_Comm_rank(MPI_COMM_WORLD, &rank);
    MPI_Comm_size(MPI_COMM_WORLD, &size);

    uint64_t secret = DEFAULT_SECRET;
    int bits = DEFAULT_BITS;
    const char *text = DEFAULT_MSG;

    if (argc > 1) secret = strtoull(argv[1], NULL, 10);
    if (argc > 2) bits = atoi(argv[2]);
    if (argc > 3) text = argv[3];

    size_t len = strlen(text);
    int bad = (bits < 1 || bits > 40 || len < PREFIX_LEN || len > MAX_MSG_LEN);
    if (!bad && secret >= (UINT64_C(1) << bits)) bad = 1;
    if (bad) {
        if (rank == 0) {
            fprintf(stderr, "Uso: %s [clave < 2^bits] [bits_rango 1..40] "
                    "[mensaje de %d a %d bytes]\n",
                    argv[0], PREFIX_LEN, MAX_MSG_LEN);
        }
        MPI_Finalize();
        return EXIT_FAILURE;
    }

    uint64_t total = UINT64_C(1) << bits;
    const unsigned char *msg = (const unsigned char *)text;
    int msg_len = (int)len;

    unsigned char iv[BLOCK_LEN];
    unsigned char cipher[MAX_MSG_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char plain[MAX_MSG_LEN + EVP_MAX_BLOCK_LENGTH] = {0};
    int cipher_len = 0;

    /* El proceso 0 prepara el cifrado y lo comparte con los demas. */
    if (rank == 0) {
        if (RAND_bytes(iv, sizeof iv) != 1) fail("Error al generar el IV.");
        cipher_len = encrypt_message(secret, iv, msg, msg_len, cipher);
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

    uint64_t found = UINT64_MAX;     /* mejor clave encontrada por este proceso */
    uint64_t global_found = UINT64_MAX;
    uint64_t tested = 0;

    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    for (uint64_t r = 0; r < rounds && global_found == UINT64_MAX; r++) {
        uint64_t chunk = r * (uint64_t)size + (uint64_t)rank;

        if (chunk < num_chunks) {
            uint64_t lo = chunk * CHUNK;
            uint64_t hi = lo + CHUNK;
            if (hi > total) hi = total;

            for (uint64_t k = lo; k < hi; k++) {
                tested++;
                if (quick_check(k, iv, cipher, msg) &&
                    full_check(k, iv, cipher, cipher_len, msg, msg_len,
                               plain)) {
                    found = k;
                    break;
                }
            }
        }

        /* Todos conocen si alguien encontro la clave (la menor). */
        MPI_Allreduce(&found, &global_found, 1, MPI_UINT64_T, MPI_MIN,
                      MPI_COMM_WORLD);
    }

    double elapsed = MPI_Wtime() - start;

    double max_elapsed = 0.0;
    uint64_t total_tested = 0;
    MPI_Reduce(&elapsed, &max_elapsed, 1, MPI_DOUBLE, MPI_MAX, 0,
               MPI_COMM_WORLD);
    MPI_Reduce(&tested, &total_tested, 1, MPI_UINT64_T, MPI_SUM, 0,
               MPI_COMM_WORLD);

    /* Quien encontro la clave ya tiene el mensaje descifrado. */
    if (found != UINT64_MAX && found == global_found && rank != 0) {
        MPI_Send(plain, msg_len, MPI_UNSIGNED_CHAR, 0, 1, MPI_COMM_WORLD);
    }
    if (rank == 0) {
        int owner_is_root = (found != UINT64_MAX && found == global_found);
        if (global_found != UINT64_MAX && !owner_is_root) {
            MPI_Recv(plain, msg_len, MPI_UNSIGNED_CHAR, MPI_ANY_SOURCE, 1,
                     MPI_COMM_WORLD, MPI_STATUS_IGNORE);
        }

        printf("Rango: 2^%d = %" PRIu64 " candidatas | procesos: %d\n",
               bits, total, size);
        if (global_found != UINT64_MAX) {
            printf("Clave encontrada: %" PRIu64 "\n", global_found);
            printf("Mensaje: %.*s\n", msg_len, plain);
        } else {
            printf("No se encontro la clave.\n");
        }
        printf("Ejecucion: paralela (Open MPI, %d procesos)\n", size);
        printf("Tiempo: %.6f segundos\n", max_elapsed);
        printf("Claves probadas (total): %" PRIu64 "\n", total_tested);
        printf("Claves por segundo: %.0f\n",
               max_elapsed > 0 ? total_tested / max_elapsed : 0.0);
    }

    OPENSSL_cleanse(plain, sizeof plain);
    OPENSSL_cleanse(cipher, sizeof cipher);
    EVP_CIPHER_CTX_free(g_fast);
    EVP_CIPHER_CTX_free(g_full);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
