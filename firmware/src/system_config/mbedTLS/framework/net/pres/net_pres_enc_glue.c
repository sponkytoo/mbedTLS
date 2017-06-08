/*******************************************************************************
 Source file for the Net Pres Encryption glue functions to work with Harmony


  Summary:


  Description:

 *******************************************************************************/

/*******************************************************************************
File Name: net_pres_enc_glue.c
Copyright (c) 2013 released Microchip Technology Inc.  All rights
reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED ?AS IS? WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
 *******************************************************************************/

#include <time.h>

#include "net_pres_enc_glue.h"
#include "net/pres/net_pres_transportapi.h"
#include "net/pres/net_pres_certstore.h"

#include "config.h"
#include "wolfssl/ssl.h"
#include "wolfssl/wolfcrypt/logging.h"
#include "wolfssl/wolfcrypt/random.h"

#include "app.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"

#endif

#define NPEG_DEBUG_PRINT(fmt, ...) SYS_CMD_PRINT_BLOCKING(fmt, ##__VA_ARGS__)
//#define NPEG_DEBUG_PRINT(fmt, ...) {SYS_CONSOLE_PRINT(fmt, ##__VA_ARGS__);while(U2STAbits.UTXBF == 1);}
//#define NPEG_DEBUG_PRINT(fmt, ...) {SYS_CONSOLE_PRINT(fmt, ##__VA_ARGS__);vTaskDelay(5 / portTICK_PERIOD_MS);}
//#define NPEG_DEBUG_PRINT(fmt, ...) 

bool Get_NTP_Time(void);


void SYS_CMD_PRINT_BLOCKING(const char* format, ...)
{
    char tmpBuf[SYS_CMD_PRINT_BUFFER_SIZE];
    uint32_t ix;
    size_t len = 0;
    va_list args;
    va_start( args, format );

    len = vsnprintf(tmpBuf, SYS_CMD_PRINT_BUFFER_SIZE, format, args);

    va_end( args );

    tmpBuf[len] = '\0';

    ix = 0;
    while (len) {
        while (PLIB_USART_TransmitterBufferIsFull(SYS_DEBUG_UART_IDX));
        PLIB_USART_TransmitterByteSend(SYS_DEBUG_UART_IDX, tmpBuf[ix++]);
        len--;
    }    

}

/* Repository of Documentation and Issuing CA Certificates:
 *    https://pki.google.com/
 *    Google's Issuing CA certificate
 *    Google Internet Authority G2
 *    https://wiki.openssl.org/index.php/Binaries 
 * 
 *  openssl x509 -inform DER -outform PEM -in GIAG2.crt -out GIAG2.pem
 * 
 */
const uint8_t GIAG2_crt[] = {
    "-----BEGIN CERTIFICATE-----\r\n"
    "MIID8DCCAtigAwIBAgIDAjqSMA0GCSqGSIb3DQEBCwUAMEIxCzAJBgNVBAYTAlVT\r\n"
    "MRYwFAYDVQQKEw1HZW9UcnVzdCBJbmMuMRswGQYDVQQDExJHZW9UcnVzdCBHbG9i\r\n"
    "YWwgQ0EwHhcNMTUwNDAxMDAwMDAwWhcNMTcxMjMxMjM1OTU5WjBJMQswCQYDVQQG\r\n"
    "EwJVUzETMBEGA1UEChMKR29vZ2xlIEluYzElMCMGA1UEAxMcR29vZ2xlIEludGVy\r\n"
    "bmV0IEF1dGhvcml0eSBHMjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n"
    "AJwqBHdc2FCROgajguDYUEi8iT/xGXAaiEZ+4I/F8YnOIe5a/mENtzJEiaB0C1NP\r\n"
    "VaTOgmKV7utZX8bhBYASxF6UP7xbSDj0U/ck5vuR6RXEz/RTDfRK/J9U3n2+oGtv\r\n"
    "h8DQUB8oMANA2ghzUWx//zo8pzcGjr1LEQTrfSTe5vn8MXH7lNVg8y5Kr0LSy+rE\r\n"
    "ahqyzFPdFUuLH8gZYR/Nnag+YyuENWllhMgZxUYi+FOVvuOAShDGKuy6lyARxzmZ\r\n"
    "EASg8GF6lSWMTlJ14rbtCMoU/M4iarNOz0YDl5cDfsCx3nuvRTPPuj5xt970JSXC\r\n"
    "DTWJnZ37DhF5iR43xa+OcmkCAwEAAaOB5zCB5DAfBgNVHSMEGDAWgBTAephojYn7\r\n"
    "qwVkDBF9qn1luMrMTjAdBgNVHQ4EFgQUSt0GFhu89mi1dvWBtrtiGrpagS8wDgYD\r\n"
    "VR0PAQH/BAQDAgEGMC4GCCsGAQUFBwEBBCIwIDAeBggrBgEFBQcwAYYSaHR0cDov\r\n"
    "L2cuc3ltY2QuY29tMBIGA1UdEwEB/wQIMAYBAf8CAQAwNQYDVR0fBC4wLDAqoCig\r\n"
    "JoYkaHR0cDovL2cuc3ltY2IuY29tL2NybHMvZ3RnbG9iYWwuY3JsMBcGA1UdIAQQ\r\n"
    "MA4wDAYKKwYBBAHWeQIFATANBgkqhkiG9w0BAQsFAAOCAQEACE4Ep4B/EBZDXgKt\r\n"
    "10KA9LCO0q6z6xF9kIQYfeeQFftJf6iZBZG7esnWPDcYCZq2x5IgBzUzCeQoY3IN\r\n"
    "tOAynIeYxBt2iWfBUFiwE6oTGhsypb7qEZVMSGNJ6ZldIDfM/ippURaVS6neSYLA\r\n"
    "EHD0LPPsvCQk0E6spdleHm2SwaesSDWB+eXknGVpzYekQVA/LlelkVESWA6MCaGs\r\n"
    "eqQSpSfzmhCXfVUDBvdmWF9fZOGrXW2lOUh1mEwpWjqN0yvKnFUEv/TmFNWArCbt\r\n"
    "F4mmk2xcpMy48GaOZON9muIAs0nH5Aqq3VuDx3CQRk6+0NtZlmwu9RY23nHMAcIS\r\n"
    "wSHGFg==\r\n"
    "-----END CERTIFICATE-----\r\n"
};


#define DEBUG_LEVEL 1   

#define mbedtls_free      free
#define mbedtls_calloc    my_calloc

typedef union {
    uint64_t u64;
    uint32_t u32[2];
    uint8_t u8[8];
} epoche_t;

typedef struct {
    mbedtls_net_context server_fd;
    uint32_t flags;
    char *pers;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    char *server_name;
} mbedtls_context_t;
mbedtls_context_t mbed_ctx;

typedef struct {
    mbedtls_context_t *mbedtls_context;
    NET_PRES_TransportObject *transObject;
    bool isInited;
} net_pres_mbedTLSInfo;


typedef struct {
    WOLFSSL_CTX *wolfssl_context;
    NET_PRES_TransportObject *transObject;
    bool isInited;
} net_pres_wolfsslInfo;

mbedtls_ssl_session saved_session;

void *my_calloc(size_t n, size_t ElementSize) {
    void *p;
    uint32_t size = n * ElementSize;

    p = malloc(size);
    memset(p, 0, size);
    return p;
}

void print_heap(uint32_t x) {
    static uint32_t val_old = 0;

    uint32_t FreeBytes = xPortGetFreeHeapSize();
    uint32_t AllocatedBytes = configTOTAL_HEAP_SIZE - FreeBytes;
    NPEG_DEBUG_PRINT("Heap (Max/Alloc/Free/Diff): %d/%d/%d/%d - %d\r\n", configTOTAL_HEAP_SIZE, AllocatedBytes, FreeBytes, FreeBytes - val_old, x);
    val_old = FreeBytes;
}


// Temporary fix till crypto library is upgraded to recent wolfssl versions.

int InitRng(RNG* rng) {
    return wc_InitRng(rng);
}

static void my_debug(void *ctx, int level,
        const char *file, int line,
        const char *str);

uintptr_t GetHostName(void);
void GetTimeString(char *str);

/*******************************************************************************
 *        
 *                            Stream Client 1: mbedTLS
 * 
 ******************************************************************************/
// <editor-fold defaultstate="collapsed" desc="Stream Client 1 Functions">

NET_PRES_EncProviderObject net_pres_EncProviderStreamClient1 = {
    .fpInit = NET_PRES_EncProviderStreamClientInit1,
    .fpDeinit = NET_PRES_EncProviderStreamClientDeinit1,
    .fpOpen = NET_PRES_EncProviderStreamClientOpen1,
    .fpConnect = NET_PRES_EncProviderClientConnect1,
    .fpClose = NET_PRES_EncProviderConnectionClose1,
    .fpWrite = NET_PRES_EncProviderWrite1,
    .fpWriteReady = NET_PRES_EncProviderWriteReady1,
    .fpRead = NET_PRES_EncProviderRead1,
    .fpReadReady = NET_PRES_EncProviderReadReady1,
    .fpPeek = NET_PRES_EncProviderPeek1,
    .fpIsInited = NET_PRES_EncProviderStreamClientIsInited1,
};
net_pres_mbedTLSInfo net_pres_mbedTLSInfoStreamClient1;

int NET_PRES_EncGlue_StreamClientReceiveCb1(void *ctx, unsigned char *buf, size_t len) {
    uint16_t bufferSize;
    uint16_t ncount = 0;
    int fd = ((mbedtls_net_context *) ctx)->fd;

    if (fd < 0)
        return ( MBEDTLS_ERR_NET_INVALID_CONTEXT);

    do {
        bufferSize = (*net_pres_mbedTLSInfoStreamClient1.transObject->fpRead)((uintptr_t) fd, (uint8_t*) buf, len);
        buf += bufferSize;
        len -= bufferSize;
        ncount += bufferSize;
        if (len)vTaskDelay(50 / portTICK_PERIOD_MS);
    } while (len);

    return ncount;
}

int NET_PRES_EncGlue_StreamClientSendCb1(void *ctx, const unsigned char *buf, size_t len) {
    int fd = *(int *) ctx;
    uint16_t bufferSize;

    bufferSize = (*net_pres_mbedTLSInfoStreamClient1.transObject->fpWrite)((uintptr_t) fd, (uint8_t*) buf, (uint16_t) len);

    return bufferSize;
}

uint32_t ssl_init_flag = 0;

bool NET_PRES_EncProviderStreamClientInit1(NET_PRES_TransportObject * transObject) {
    int ret = 0;

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold(DEBUG_LEVEL);
#endif

    NPEG_DEBUG_PRINT(" mbedTLS NET_PRES_EncProviderStreamClientInit1\r\n");

    /*
     * 0. Initialize the RNG and the session data
     */

    mbed_ctx.pers = "ssl_client1";

    NPEG_DEBUG_PRINT("\n  . Seeding the random number generator...");
    mbedtls_entropy_init(& mbed_ctx.entropy);

    if ((ret = mbedtls_ctr_drbg_seed(& mbed_ctx.ctr_drbg, mbedtls_entropy_func, & mbed_ctx.entropy,
            (const unsigned char *) mbed_ctx.pers,
            strlen(mbed_ctx.pers))) != 0) {
        NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\r\n", ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return ret;
    }

    NPEG_DEBUG_PRINT(" ok\r\n");

    net_pres_mbedTLSInfoStreamClient1.transObject = transObject;
    net_pres_mbedTLSInfoStreamClient1.mbedtls_context = &mbed_ctx;
    if (net_pres_mbedTLSInfoStreamClient1.mbedtls_context == 0) {
        return false;
    }

    mbed_ctx.pers = "ssl_client1";
    mbedtls_net_init(& mbed_ctx.server_fd);
    mbedtls_ssl_init(& mbed_ctx.ssl);
    mbedtls_ssl_config_init(& mbed_ctx.conf);
    mbedtls_x509_crt_init(& mbed_ctx.cacert);
    mbedtls_ctr_drbg_init(& mbed_ctx.ctr_drbg);

    NPEG_DEBUG_PRINT("\n  . Seeding the random number generator...");
    mbedtls_entropy_init(& mbed_ctx.entropy);

    if ((ret = mbedtls_ctr_drbg_seed(& mbed_ctx.ctr_drbg, mbedtls_entropy_func, & mbed_ctx.entropy,
            (const unsigned char *) mbed_ctx.pers,
            strlen(mbed_ctx.pers))) != 0) {
        NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ctr_drbg_seed returned %d\r\n", ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return ret;
    }

    NPEG_DEBUG_PRINT(" ok\r\n");

    mbedtls_ssl_set_bio(&mbed_ctx.ssl, &mbed_ctx.server_fd,
            NET_PRES_EncGlue_StreamClientSendCb1,
            NET_PRES_EncGlue_StreamClientReceiveCb1, NULL);

    /*
     * 0. Initialize certificates
     */
    NPEG_DEBUG_PRINT("  . Loading the CA root certificate ...");

    ret = mbedtls_x509_crt_parse(&mbed_ctx.cacert, (const unsigned char *) GIAG2_crt, //mbedtls_test_cas_pem,
            sizeof (GIAG2_crt)); //mbedtls_test_cas_pem_len);

    if (ret < 0) {
        NPEG_DEBUG_PRINT(" failed\r\n  !  mbedtls_x509_crt_parse returned -0x%x\r\n", -ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return ret;
    }

    mbedtls_ssl_conf_ca_chain(&mbed_ctx.conf, &mbed_ctx.cacert, NULL);
    return true;
}

bool NET_PRES_EncProviderStreamClientDeinit1() {

    NPEG_DEBUG_PRINT(" mbedTLS NET_PRES_EncProviderStreamClientDeinit1\r\n");

    net_pres_mbedTLSInfoStreamClient1.isInited = false;
    NPEG_DEBUG_PRINT(" mbedTLS Deinit Ready\r\n");

    return true;
}


uint32_t open_flag = 0;

bool NET_PRES_EncProviderStreamClientOpen1(uintptr_t transHandle, void * providerData) {
    bool ret = 0;

    NPEG_DEBUG_PRINT(" mbedTLS NET_PRES_EncProviderStreamClientOpen1 %d\r\n", transHandle);

    (&mbed_ctx)->server_fd.fd = (int) transHandle;

    /*
     * 2. Setup stuff
     */
    NPEG_DEBUG_PRINT("  . Setting up the SSL/TLS structure...");
    fflush(stdout);

    if ((ret = mbedtls_ssl_config_defaults(&mbed_ctx.conf,
            MBEDTLS_SSL_IS_CLIENT,
            MBEDTLS_SSL_TRANSPORT_STREAM,
            MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return ret;
    }

    NPEG_DEBUG_PRINT(" ok\r\n");


    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode(&mbed_ctx.conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
    mbedtls_ssl_conf_ca_chain(&mbed_ctx.conf, &mbed_ctx.cacert, NULL);
    mbedtls_ssl_conf_rng(&mbed_ctx.conf, mbedtls_ctr_drbg_random, & mbed_ctx.ctr_drbg);
    mbedtls_ssl_conf_dbg(&mbed_ctx.conf, my_debug, stdout);

    net_pres_mbedTLSInfoStreamClient1.isInited = true;

    (&mbed_ctx)->server_fd.fd = (int) transHandle;
    if ((ret = mbedtls_ssl_setup(&mbed_ctx.ssl, &mbed_ctx.conf)) != 0) {
        NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ssl_setup returned %d\r\n", ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return false;
    }

    mbed_ctx.server_name = (char *) GetHostName();
    if ((ret = mbedtls_ssl_set_hostname(&mbed_ctx.ssl, mbed_ctx.server_name)) != 0) {
        NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ssl_set_hostname returned %d\r\n", ret);
        NET_PRES_EncProviderStreamClientDeinit1();
        return false;
    }

    return true;
}

bool NET_PRES_EncProviderStreamClientIsInited1() {
    return net_pres_mbedTLSInfoStreamClient1.isInited;
}

NET_PRES_EncSessionStatus NET_PRES_EncProviderClientConnect1(void * providerData) {
    int ret;
    char str[100];

    NPEG_DEBUG_PRINT(" mbedTLS NET_PRES_EncProviderClientConnect1\r\n");

    GetTimeString(str);
    SYS_CONSOLE_PRINT("\n\rUTC-0: %s\n\r", str);

    mbedtls_ssl_set_bio(&mbed_ctx.ssl, &mbed_ctx.server_fd,
            NET_PRES_EncGlue_StreamClientSendCb1,
            NET_PRES_EncGlue_StreamClientReceiveCb1, NULL);

    NPEG_DEBUG_PRINT("  . Performing the SSL/TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&mbed_ctx.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            NPEG_DEBUG_PRINT(" failed\n\r  ! mbedtls_ssl_handshake returned -0x%x\r\n", -ret);
            NET_PRES_EncProviderStreamClientDeinit1();
            return ret;
        }
    }

    //mbedtls_ssl_get_session(&mbed_ctx.ssl, &saved_session);

    NPEG_DEBUG_PRINT("  . Verifying peer X.509 certificate...");

    /* In real life, we probably want to bail out when ret != 0 */
    if ((mbed_ctx.flags = mbedtls_ssl_get_verify_result(&mbed_ctx.ssl)) != 0) {
        char vrfy_buf[512];

        NPEG_DEBUG_PRINT(" failed\r\n");

        mbedtls_x509_crt_verify_info(vrfy_buf, sizeof ( vrfy_buf), "  ! ", mbed_ctx.flags);

        NPEG_DEBUG_PRINT("%s\r\n", vrfy_buf);
    } else {
        NPEG_DEBUG_PRINT(" ok\r\n");
    }

    return NET_PRES_ENC_SS_OPEN;
}

NET_PRES_EncSessionStatus NET_PRES_EncProviderConnectionClose1(void * providerData) {

    NPEG_DEBUG_PRINT(" mbedTLS NET_PRES_EncProviderConnectionClose1\r\n");

    mbedtls_ssl_close_notify(&mbed_ctx.ssl);
    mbedtls_ssl_free(&mbed_ctx.ssl);

    return NET_PRES_ENC_SS_CLOSED;
}

int32_t NET_PRES_EncProviderWrite1(void * providerData, const uint8_t * buffer, uint16_t size) {
    int ret;
    //    NPEG_DEBUG_PRINT(" mbedTLS Write %d\r\n", size);
    while ((ret = mbedtls_ssl_write(&mbed_ctx.ssl, buffer, size)) <= 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            //            NPEG_DEBUG_PRINT(" failed\n  ! mbedtls_ssl_write returned %d\r\n", ret);
            NET_PRES_EncProviderStreamClientDeinit1();
        }
    }
    return ret;
}

uint16_t NET_PRES_EncProviderWriteReady1(void * providerData, uint16_t reqSize, uint16_t minSize) {
    return reqSize;
}

int32_t NET_PRES_EncProviderRead1(void * providerData, uint8_t * buffer, uint16_t size) {
    int ret;
    ret = mbedtls_ssl_read(&mbed_ctx.ssl, buffer, size);
    return ret;
}

int32_t NET_PRES_EncProviderReadReady1(void * providerData) {
    int ret = 0;

    ret = (*net_pres_mbedTLSInfoStreamClient1.transObject->fpReadyToRead)((uintptr_t) mbed_ctx.server_fd.fd);

    return ret;
}

int32_t NET_PRES_EncProviderPeek1(void * providerData, uint8_t * buffer, uint16_t size) {
    return 0;
}

/*
 * Initialize a context
 */
void mbedtls_net_init(mbedtls_net_context *ctx) {
    ctx->fd = -1;
}

/*
 * Gracefully close the connection
 */
void mbedtls_net_free(mbedtls_net_context *ctx) {
    if (ctx->fd == -1)
        return;

    ctx->fd = -1;
}

static void my_debug(void *ctx, int level,
        const char *file, int line,
        const char *str) {
    ((void) level);

    NPEG_DEBUG_PRINT("%s:%04d: %s\r\n", file, line, str);
}
// </editor-fold>

// <editor-fold defaultstate="collapsed" desc="UTC to Time Functions for NTP">

typedef struct {
    unsigned char second; // 0-59
    unsigned char minute; // 0-59
    unsigned char hour; // 0-23
    unsigned char day; // 1-31
    unsigned char month; // 1-12
    unsigned char year; // 0-99 (representing 2000-2099)
} date_time_t;


static unsigned short days[4][12] = {
    { 0, 31, 60, 91, 121, 152, 182, 213, 244, 274, 305, 335},
    { 366, 397, 425, 456, 486, 517, 547, 578, 609, 639, 670, 700},
    { 731, 762, 790, 821, 851, 882, 912, 943, 974, 1004, 1035, 1065},
    {1096, 1127, 1155, 1186, 1216, 1247, 1277, 1308, 1339, 1369, 1400, 1430},
};

//
//unsigned int date_time_to_epoch(date_time_t* date_time)
//{
//    unsigned int second = date_time->second;  // 0-59
//    unsigned int minute = date_time->minute;  // 0-59
//    unsigned int hour   = date_time->hour;    // 0-23
//    unsigned int day    = date_time->day-1;   // 0-30
//    unsigned int month  = date_time->month-1; // 0-11
//    unsigned int year   = date_time->year;    // 0-99
//    return (((year/4*(365*4+1)+days[year%4][month]+day)*24+hour)*60+minute)*60+second;
//}

void epoch_to_date_time(date_time_t* date_time, unsigned int epoch) {
    /* The function epoch_to_date_time() does only work from 1.1.2000
     * And the NTC timestamp starts from the 1.1.1900
     * 
     * 2208988800 seconds between 1.1.1900 and 1.1.1970
     * 946684800  seconds between 1.1.1970 and 1.1.2000
     * 3155673600 seconds between 1.1.1900 and 1.1.2000
     * 
     * See: https://www.aelius.com/njh/unixtime/?y=1900&m=1&d=1&h=0&i=0&s=0     
     */

    /* 946684800 => seconds between 1.1.1970 and 1.1.2000 */
    epoch -= 946684800;

    date_time->second = epoch % 60;
    epoch /= 60;
    date_time->minute = epoch % 60;
    epoch /= 60;
    date_time->hour = epoch % 24;
    epoch /= 24;

    unsigned int years = epoch / (365 * 4 + 1)*4;
    epoch %= 365 * 4 + 1;

    unsigned int year;
    for (year = 3; year > 0; year--) {
        if (epoch >= days[year][0])
            break;
    }

    unsigned int month;
    for (month = 11; month > 0; month--) {
        if (epoch >= days[year][month])
            break;
    }

    date_time->year = years + year;
    date_time->month = month + 1;
    date_time->day = epoch - days[year][month] + 1;
}

bool Get_NTP_Time(void) {
    uint32_t LastUpdate = 0;
    date_time_t MyTime;
    epoche_t MyEpocheRcv, MyEpoche;
    int count = 30;

    SYS_CONSOLE_PRINT("\r\nNTP");
    MyEpocheRcv.u32[0] = 0;
    do {
        vTaskDelay(500 / portTICK_PERIOD_MS);
        SYS_CONSOLE_PRINT(".");
        TCPIP_SNTP_TimeStampGet(&MyEpocheRcv.u64, &LastUpdate);
        if (--count == 0) {
            SYS_CONSOLE_PRINT("\r\n NTP Timeout\r\n");
            return false;
        }
    } while (MyEpocheRcv.u32[0] == 0);
    SYS_CONSOLE_PRINT("\r");
    SYS_CONSOLE_PRINT("NTP: %08x:%08x  => ", MyEpocheRcv.u32[0], MyEpocheRcv.u32[1]);
    MyEpoche.u32[0] = TCPIP_SNTP_UTCSecondsGet();

    SYS_CONSOLE_PRINT("UTC-0(No Summertime): %d  => ", MyEpoche.u32[0]);

    epoch_to_date_time(&MyTime, MyEpoche.u32[0]);

    SYS_CONSOLE_PRINT("%02d.%02d.%02d %02d:%02d:%02d \r\n", MyTime.day, MyTime.month, MyTime.year + 2000, MyTime.hour, MyTime.minute, MyTime.second);
    return true;

}

void GetTimeString(char *str) {
    epoche_t MyEpoche;
    date_time_t MyTime;

    MyEpoche.u32[0] = TCPIP_SNTP_UTCSecondsGet();
    epoch_to_date_time(&MyTime, MyEpoche.u32[0]);
    sprintf(str, "%02d.%02d.%02d %02d:%02d:%02d", MyTime.day, MyTime.month, MyTime.year + 2000, MyTime.hour, MyTime.minute, MyTime.second);
}

int gettimeofday(void *pTime, void *p) {
    uint32_t LastUpdate = 0;
    TCPIP_SNTP_TimeStampGet((uint64_t*) pTime, &LastUpdate);
    return 0;
}

time_t time(time_t *t) {
    epoche_t my_epoche;
    my_epoche.u32[0] = TCPIP_SNTP_UTCSecondsGet();
    return my_epoche.u32[0];
}

struct tm * gmtime(const time_t *pTime) {
    date_time_t MyTime;
    epoche_t MyEpoche;
    static struct tm MyTimeStruct;

    MyEpoche.u32[0] = *pTime;
    epoch_to_date_time(&MyTime, MyEpoche.u32[0]);

    MyTimeStruct.tm_sec = MyTime.second;
    MyTimeStruct.tm_min = MyTime.minute;
    MyTimeStruct.tm_hour = MyTime.hour;
    MyTimeStruct.tm_mday = MyTime.day;
    MyTimeStruct.tm_mon = MyTime.month - 1;
    MyTimeStruct.tm_year = (MyTime.year + 2000) - 1900;

    return &MyTimeStruct;
}

// </editor-fold>
