/*----------------------------------------------------------------------
 * UNIVERSIDAD DEL VALLE DE GUATEMALA
 * Curso:       CC3069 - Computacion Paralela y Distribuida
 * Proyecto 2:  Busqueda paralela (Open MPI) - ESTRATEGIA ALTERNATIVA
 *              (zona prioritaria + regiones multiorigen + aviso
 *               asincrono + API de bajo nivel de OpenSSL)
 *
 * Autores:
 *  - Angie Nadissa Vela Lopez, 23764
 *  - Roberto Camposeco Torres, 23968
 *  - Javier Alexander Linares Chang, 231135
 *
 * Combina cuatro mecanismos respecto a la estrategia base
 * (busqueda_clave_aes_mpi.c):
 *
 *   1. Zona prioritaria (criterio greedy). Z1 = [0, 2^24) (recortada a
 *      [0, total) si el rango pedido es menor). Se reparte en 'size'
 *      franjas iguales y la explora TODO el equipo de procesos antes de
 *      pasar a su region.
 *   2. Regiones multiorigen para el resto del espacio T \ Z1. Los
 *      limites de las regiones son los mismos cuartos naturales de T
 *      (0, T/4, T/2, 3T/4, T); SOLO la region del proceso 0 se recorta
 *      por Z1 (pasa a [Z1, T/size)), las demas quedan identicas. Asi
 *      2^54 y 2^54+1 siguen cayendo exactamente al inicio de la region
 *      del proceso 1, sin cambios. Cada candidata pertenece a Z1 o a
 *      una sola region: no se omite ni se repite ninguna.
 *   3. Aviso asincrono en lugar de sincronizacion por ronda. Se elimina
 *      el MPI_Allreduce POR RONDA. El proceso que encuentra la clave
 *      notifica a todos los demas con MPI_Isend (no bloqueante); cada
 *      proceso revisa cada POLL_EVERY candidatas con MPI_Test sobre un
 *      MPI_Irecv publicado al inicio. Al terminar todo el trabajo local
 *      (por hallazgo, aviso recibido, o agotar el espacio), se hace UN
 *      UNICO MPI_Allreduce final para fijar el resultado global de forma
 *      segura, sin que esto implique sincronizar cada pocos miles de
 *      candidatas como en la estrategia base.
 *   4. Reduccion del costo por candidata. El filtro rapido usa la
 *      interfaz de BAJO NIVEL de OpenSSL (AES_set_decrypt_key +
 *      AES_decrypt) en lugar de EVP, evitando su despacho generico.
 *      El encadenamiento CBC se hace a mano: el bloque 2 se descifra
 *      XOR con el BLOQUE DE CIFRADO 1 (no con el IV original). La
 *      confirmacion completa (full_check) sigue usando EVP con
 *      validacion de relleno PKCS7, porque ocurre con muy poca
 *      frecuencia (solo cuando el filtro rapido ya dio positivo).
 *
 * Compilacion:
 *   mpicc -std=c11 -O2 -Wall -Wextra busqueda_clave_aes_mpi_alt.c \
 *         -o busqueda_clave_aes_mpi_alt -lcrypto
 * Uso:
 *   mpirun -np 4 ./busqueda_clave_aes_mpi_alt <archivo.txt>
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
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#define BLOCK_LEN      16
#define MAX_MSG_LEN    4096
#define PHRASE_LEN     16
#define MAX_BITS       56
#define DEFAULT_BITS   56
#define NOT_FOUND      UINT64_MAX
#define PRIORITY_ZONE  (UINT64_C(1) << 24)   /* Z1: tamano de la zona prioritaria */
#define POLL_EVERY     (UINT64_C(1) << 14)   /* candidatas entre cada MPI_Test */
#define TAG_FOUND      77

static const unsigned char PHRASE[PHRASE_LEN + 1] = "es una prueba de";

static EVP_CIPHER_CTX *g_full = NULL;  /* confirmacion completa, con padding */

static void fail(const char *description)
{
    fprintf(stderr, "%s\n", description);
    ERR_print_errors_fp(stderr);
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

/* Filtro rapido con la interfaz de BAJO NIVEL de OpenSSL (mecanismo 4):
 * evita el despacho generico de EVP. Descifra los 2 primeros bloques
 * encadenando CBC a mano (bloque 2 XOR con el bloque de CIFRADO 1, no
 * con el IV) y busca la frase. */
static int quick_check_lowlevel(uint64_t candidate, const unsigned char *iv,
                                 const unsigned char *cipher)
{
    unsigned char key[16];
    make_key(candidate, key);

    AES_KEY aes_key;
    AES_set_decrypt_key(key, 128, &aes_key);
    OPENSSL_cleanse(key, sizeof key);

    unsigned char dec[16], buf[2 * BLOCK_LEN];

    /* bloque 1: AES_decrypt(C1) XOR IV */
    AES_decrypt(cipher, dec, &aes_key);
    for (int i = 0; i < BLOCK_LEN; i++) buf[i] = dec[i] ^ iv[i];

    /* bloque 2: AES_decrypt(C2) XOR C1 (el bloque de CIFRADO 1, no el IV) */
    AES_decrypt(cipher + BLOCK_LEN, dec, &aes_key);
    for (int i = 0; i < BLOCK_LEN; i++) buf[BLOCK_LEN + i] = dec[i] ^ cipher[i];

    return find_phrase(buf, 2 * BLOCK_LEN) >= 0;
}

/* Confirmacion completa (poco frecuente): EVP con validacion de relleno. */
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

/* Recorre [lo, hi). Revisa aviso ajeno cada POLL_EVERY candidatas via
 * MPI_Test sobre recv_req. Si encuentra la clave, notifica a los demas
 * con MPI_Isend y devuelve 1. Si recibe aviso ajeno, devuelve 0 con
 * *stop=1. Actualiza *tried con las candidatas efectivamente probadas. */
static int scan_range(uint64_t lo, uint64_t hi, int rank, int size,
                       const unsigned char *iv, const unsigned char *cipher,
                       int cipher_len, unsigned char *plain, int *plain_len,
                       uint64_t *tried, MPI_Request *recv_req, int *stop,
                       uint64_t *found_key, MPI_Request send_reqs[])
{
    for (uint64_t k = lo; k < hi; k++) {
        (*tried)++;
        if (quick_check_lowlevel(k, iv, cipher) &&
            full_check(k, iv, cipher, cipher_len, plain, plain_len)) {
            *found_key = k;
            for (int dst = 0; dst < size; dst++) {
                if (dst == rank) continue;
                MPI_Isend(found_key, 1, MPI_UNSIGNED_LONG_LONG, dst,
                          TAG_FOUND, MPI_COMM_WORLD, &send_reqs[dst]);
            }
            *stop = 1;
            return 1;
        }
        if ((*tried % POLL_EVERY) == 0) {
            int flag = 0;
            MPI_Test(recv_req, &flag, MPI_STATUS_IGNORE);
            if (flag) { *stop = 1; return 0; }
        }
    }
    return 0;
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

    g_full = EVP_CIPHER_CTX_new();
    unsigned char zero[16] = {0};
    if (g_full == NULL ||
        EVP_DecryptInit_ex(g_full, EVP_aes_128_cbc(), NULL, zero, iv) != 1) {
        fail("Error al preparar el contexto de confirmacion.");
    }

    /* ---- Mecanismo 1 y 2: zona prioritaria + regiones multiorigen ---- */
    const uint64_t Z1 = (total < PRIORITY_ZONE) ? total : PRIORITY_ZONE;

    uint64_t b_lo, b_hi;               /* limites naturales de la region de este rank */
    b_lo = (uint64_t)rank * (total / (uint64_t)size);
    b_hi = (rank == size - 1) ? total : (uint64_t)(rank + 1) * (total / (uint64_t)size);

    uint64_t z1_lo = (uint64_t)rank * (Z1 / (uint64_t)size);
    uint64_t z1_hi = (rank == size - 1) ? Z1 : (uint64_t)(rank + 1) * (Z1 / (uint64_t)size);

    uint64_t region_lo = (rank == 0) ? (Z1 > b_lo ? Z1 : b_lo) : b_lo;
    uint64_t region_hi = b_hi;

    /* ---- Mecanismo 3: aviso asincrono ---- */
    uint64_t incoming_key = 0;
    MPI_Request recv_req;
    MPI_Irecv(&incoming_key, 1, MPI_UNSIGNED_LONG_LONG, MPI_ANY_SOURCE,
              TAG_FOUND, MPI_COMM_WORLD, &recv_req);
    MPI_Request send_reqs[64];
    for (int i = 0; i < size && i < 64; i++) send_reqs[i] = MPI_REQUEST_NULL;

    uint64_t found = NOT_FOUND, tested = 0;
    int stop = 0, i_found = 0;

    MPI_Barrier(MPI_COMM_WORLD);
    double start = MPI_Wtime();

    /* Fase 1: zona prioritaria */
    i_found = scan_range(z1_lo, z1_hi, rank, size, iv, cipher, cipher_len,
                          plain, &plain_len, &tested, &recv_req, &stop, &found, send_reqs);

    /* Fase 2: region propia del resto del espacio */
    if (!stop) {
        i_found = scan_range(region_lo, region_hi, rank, size, iv, cipher, cipher_len,
                              plain, &plain_len, &tested, &recv_req, &stop, &found, send_reqs);
    }

    double elapsed = MPI_Wtime() - start;

    /* Si el aviso vino de otro proceso, solo se consume la solicitud ya
     * completada; 'found' se deja en NOT_FOUND para ESTE proceso, porque
     * el que realmente encontro la clave es quien la mando (el Allreduce
     * final decide el valor global a partir de ahi, no 'incoming_key'). */
    if (stop && !i_found) {
        MPI_Wait(&recv_req, MPI_STATUS_IGNORE);
        (void)incoming_key;
    } else {
        int rflag = 0;
        MPI_Test(&recv_req, &rflag, MPI_STATUS_IGNORE);
        if (!rflag) { MPI_Cancel(&recv_req); MPI_Wait(&recv_req, MPI_STATUS_IGNORE); }
    }
    for (int i = 0; i < size && i < 64; i++)
        if (send_reqs[i] != MPI_REQUEST_NULL) MPI_Wait(&send_reqs[i], MPI_STATUS_IGNORE);

    /* Un unico Allreduce FINAL (no por ronda) para fijar el resultado
     * global de forma segura, ya que el trabajo local de cada proceso
     * no termina exactamente al mismo tiempo. */
    uint64_t global_found = NOT_FOUND;
    MPI_Allreduce(&found, &global_found, 1, MPI_UINT64_T, MPI_MIN, MPI_COMM_WORLD);

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
        printf("=== Resultado (rango 2^%d = %" PRIu64 ", Z1 = %" PRIu64 ") ===\n",
               bits, total, Z1);
        if (global_found != NOT_FOUND) {
            unsigned char key128[16];
            make_key(global_found, key128);
            printf("Clave encontrada: %" PRIu64 "\n", global_found);
            printf("Clave (128 bits): "); print_hex(key128, 16);
            if (quick_check_lowlevel(global_found, iv, cipher) &&
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
        printf("\nEjecucion: paralela alternativa (zona prioritaria + multiorigen "
               "+ aviso asincrono + AES bajo nivel, %d procesos)\n", size);
        printf("Tiempo total (max entre procesos): %.6f segundos\n", tmax);
        printf("Candidatas probadas (total): %" PRIu64 "\n", ttot);
        printf("Claves por segundo (agregado): %.0f\n", tmax > 0 ? (double)ttot / tmax : 0.0);
        free(g_tested); free(g_time); free(g_owner);
    }

    OPENSSL_cleanse(plain, sizeof plain);
    OPENSSL_cleanse(cipher, sizeof cipher);
    OPENSSL_cleanse(msg, sizeof msg);
    EVP_CIPHER_CTX_free(g_full);
    MPI_Finalize();
    return EXIT_SUCCESS;
}
