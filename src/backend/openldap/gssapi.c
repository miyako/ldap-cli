#include <CoreFoundation/CoreFoundation.h>
#include <GSS/GSS.h>
#include <ldap.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <string.h>

static void gss_error(char *error, size_t size, const char *stage,
                      OM_uint32 major, OM_uint32 minor)
{
    OM_uint32 ignored, context = 0;
    gss_buffer_desc message = GSS_C_EMPTY_BUFFER;
    snprintf(error, size, "%s: GSS major 0x%08x, minor 0x%08x",
             stage, major, minor);
    if (GSS_ROUTINE_ERROR(major) == GSS_S_BAD_BINDINGS) {
        size_t used = strlen(error);
        snprintf(error + used, size - used, " (channel binding rejected)");
    }
    if (gss_display_status(&ignored, minor, GSS_C_MECH_CODE,
                           GSS_KRB5_MECHANISM, &context, &message) == GSS_S_COMPLETE) {
        size_t used = strlen(error);
        snprintf(error + used, size - used, ": %.*s",
                 (int)message.length, (char *)message.value);
        gss_release_buffer(&ignored, &message);
    }
}

static OM_uint32 import_name(const char *text, gss_OID type,
                             gss_name_t *name, OM_uint32 *minor)
{
    gss_buffer_desc value = {strlen(text), (void *)text};
    return gss_import_name(minor, &value, type, name);
}

static int endpoint_binding(LDAP *ld, unsigned char *data, size_t *length,
                             char *error, size_t error_size)
{
    SSL *ssl = NULL;
    if (ldap_get_option(ld, LDAP_OPT_X_TLS_SSL_CTX, &ssl) != LDAP_OPT_SUCCESS || !ssl) {
        snprintf(error, error_size, "channel binding: TLS session unavailable");
        return 0;
    }
    X509 *cert = SSL_get1_peer_certificate(ssl);
    if (!cert) {
        snprintf(error, error_size, "channel binding: peer certificate unavailable");
        return 0;
    }
    int md_nid, pk_nid, bits;
    uint32_t flags;
    int ok = X509_get_signature_info(cert, &md_nid, &pk_nid, &bits, &flags);
    if (ok && (md_nid == NID_md5 || md_nid == NID_sha1 || md_nid == NID_md5_sha1))
        md_nid = NID_sha256;
    const EVP_MD *md = ok ? EVP_get_digestbynid(md_nid) : NULL;
    const char prefix[] = "tls-server-end-point:";
    unsigned int digest_length = 0;
    ok = md && X509_digest(cert, md, data + sizeof(prefix) - 1, &digest_length);
    X509_free(cert);
    if (!ok) {
        snprintf(error, error_size, "channel binding: unsupported certificate signature digest");
        return 0;
    }
    memcpy(data, prefix, sizeof(prefix) - 1);
    *length = sizeof(prefix) - 1 + digest_length;
    return 1;
}

/* Password credentials live only in a unique MEMORY cache, never the default
 * login cache. The handle is passed directly to GSS, not selected via environment. */
static OM_uint32 acquire_password(gss_name_t name, const unsigned char *password,
                                  size_t password_length, gss_cred_id_t *cred,
                                  char *error, size_t error_size)
{
    CFUUIDRef uuid = CFUUIDCreate(NULL);
    CFStringRef uuid_text = CFUUIDCreateString(NULL, uuid);
    CFStringRef cache = CFStringCreateWithFormat(NULL, NULL, CFSTR("MEMORY:ldap-cli-%@"), uuid_text);
    CFDataRef secret = CFDataCreateWithBytesNoCopy(NULL, password,
                                                 password_length, kCFAllocatorNull);
    const void *keys[] = {kGSSICPassword, kGSSICKerberosCacheName, kGSSICCreateNewCredential};
    const void *values[] = {secret, cache, kCFBooleanTrue};
    CFDictionaryRef attributes = CFDictionaryCreate(NULL, keys, values, 3,
                                                     &kCFTypeDictionaryKeyCallBacks,
                                                     &kCFTypeDictionaryValueCallBacks);
    CFErrorRef detail = NULL;
    OM_uint32 major = gss_aapl_initial_cred(name, GSS_KRB5_MECHANISM,
                                            attributes, cred, &detail);
    if (major != GSS_S_COMPLETE) {
        snprintf(error, error_size, "explicit Kerberos credentials: GSS major 0x%08x", major);
        if (detail) {
            CFStringRef description = CFErrorCopyDescription(detail);
            char text[1024];
            if (CFStringGetCString(description, text, sizeof(text), kCFStringEncodingUTF8))
                snprintf(error, error_size, "explicit Kerberos credentials: %s", text);
            CFRelease(description);
        }
    }
    if (detail) CFRelease(detail);
    CFRelease(attributes);
    CFRelease(secret);
    CFRelease(cache);
    CFRelease(uuid_text);
    CFRelease(uuid);
    return major;
}

int ldap_cli_gssapi_bind(LDAP *ld, const char *host, const char *user,
                         const unsigned char *password, size_t password_length,
                         int use_binding, char *error, size_t error_size)
{
    OM_uint32 major, minor = 0, ignored, flags = 0;
    gss_name_t client = GSS_C_NO_NAME, service = GSS_C_NO_NAME;
    gss_cred_id_t cred = GSS_C_NO_CREDENTIAL;
    gss_ctx_id_t context = GSS_C_NO_CONTEXT;
    gss_buffer_desc output = GSS_C_EMPTY_BUFFER, plain = GSS_C_EMPTY_BUFFER;
    struct berval *server = NULL;
    int rc = LDAP_LOCAL_ERROR;
    unsigned char binding[sizeof("tls-server-end-point:") + EVP_MAX_MD_SIZE];
    struct gss_channel_bindings_struct cb = {0};
    char service_name[1024];
    error[0] = '\0';

    if (password && (!user || !*user || !password_length ||
                     memchr(password, 0, password_length))) {
        snprintf(error, error_size, "explicit GSSAPI requires a user and nonempty password without NUL");
        goto done;
    }
    if (use_binding) {
        if (!endpoint_binding(ld, binding, &cb.application_data.length, error, error_size))
            goto done;
        cb.application_data.value = binding;
    }
    if (user) {
        major = import_name(user, GSS_C_NT_USER_NAME, &client, &minor);
        if (major != GSS_S_COMPLETE) {
            gss_error(error, error_size, "user identity", major, minor);
            goto done;
        }
    }
    if (password) {
        major = acquire_password(client, password, password_length, &cred, error, error_size);
    } else {
        gss_OID_desc mechanism = *GSS_KRB5_MECHANISM;
        gss_OID_set_desc mechanisms = {1, &mechanism};
        major = gss_acquire_cred(&minor, client, 0, &mechanisms, GSS_C_INITIATE,
                                 &cred, NULL, NULL);
        if (major != GSS_S_COMPLETE)
            gss_error(error, error_size, "Kerberos SSO credentials", major, minor);
    }
    if (major != GSS_S_COMPLETE)
        goto done;
    if (cred == GSS_C_NO_CREDENTIAL) {
        snprintf(error, error_size, "GSSAPI returned no credential handle");
        goto done;
    }
    if (snprintf(service_name, sizeof(service_name), "ldap@%s", host) >= (int)sizeof(service_name)) {
        snprintf(error, error_size, "LDAP service name too long");
        goto done;
    }
    major = import_name(service_name, GSS_C_NT_HOSTBASED_SERVICE, &service, &minor);
    if (major != GSS_S_COMPLETE) {
        gss_error(error, error_size, "LDAP service identity", major, minor);
        goto done;
    }

    /* RFC 4752: finish mutual GSS authentication, then negotiate the SASL
     * no-security-layer choice inside GSS integrity protection (TLS supplies it). */
    for (unsigned int step = 0; step < 16; ++step) {
        gss_buffer_desc input = GSS_C_EMPTY_BUFFER;
        if (server) {
            input.length = server->bv_len;
            input.value = server->bv_val;
        }
        major = gss_init_sec_context(&minor, cred, &context, service, GSS_KRB5_MECHANISM,
                                     GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG | GSS_C_REPLAY_FLAG,
                                     0, use_binding ? &cb : GSS_C_NO_CHANNEL_BINDINGS,
                                     &input, NULL, &output, &flags, NULL);
        if (server) { ber_bvfree(server); server = NULL; }
        if (major != GSS_S_COMPLETE && major != GSS_S_CONTINUE_NEEDED) {
            gss_error(error, error_size, "Kerberos token exchange", major, minor);
            rc = LDAP_LOCAL_ERROR;
            goto done;
        }
        struct berval token = {output.length, output.value};
        rc = ldap_sasl_bind_s(ld, NULL, "GSSAPI", &token, NULL, NULL, &server);
        gss_release_buffer(&ignored, &output);
        if (rc != LDAP_SASL_BIND_IN_PROGRESS) {
            if (rc == LDAP_SUCCESS) {
                snprintf(error, error_size, "GSSAPI: server completed before SASL layer negotiation");
                rc = LDAP_LOCAL_ERROR;
            }
            goto done;
        }
        if (major == GSS_S_COMPLETE)
            break;
        if (step == 15) {
            snprintf(error, error_size, "GSSAPI: token exchange exceeded 16 steps");
            rc = LDAP_LOCAL_ERROR;
            goto done;
        }
    }
    rc = LDAP_LOCAL_ERROR;
    if ((flags & (GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)) !=
        (GSS_C_MUTUAL_FLAG | GSS_C_INTEG_FLAG)) {
        snprintf(error, error_size, "GSSAPI: mutual authentication and integrity were not negotiated");
        goto done;
    }
    if (!server) {
        snprintf(error, error_size, "GSSAPI: missing SASL layer offer");
        goto done;
    }
    gss_buffer_desc offer = {server->bv_len, server->bv_val};
    major = gss_unwrap(&minor, context, &offer, &plain, NULL, NULL);
    if (major != GSS_S_COMPLETE) {
        gss_error(error, error_size, "GSSAPI layer offer", major, minor);
        goto done;
    }
    if (plain.length != 4 || !(((unsigned char *)plain.value)[0] & 1)) {
        snprintf(error, error_size, "GSSAPI: server does not offer authentication-only over TLS");
        goto done;
    }
    unsigned char selection[] = {1, 0, 0, 0};
    gss_buffer_desc selected = {sizeof(selection), selection};
    major = gss_wrap(&minor, context, 0, GSS_C_QOP_DEFAULT, &selected, NULL, &output);
    if (major != GSS_S_COMPLETE) {
        gss_error(error, error_size, "GSSAPI layer selection", major, minor);
        goto done;
    }
    ber_bvfree(server);
    server = NULL;
    struct berval token = {output.length, output.value};
    rc = ldap_sasl_bind_s(ld, NULL, "GSSAPI", &token, NULL, NULL, &server);
    if (rc == LDAP_SASL_BIND_IN_PROGRESS) {
        snprintf(error, error_size, "GSSAPI: unexpected continuation after layer selection");
        rc = LDAP_LOCAL_ERROR;
    }

done:
    if (server) ber_bvfree(server);
    gss_release_buffer(&ignored, &output);
    gss_release_buffer(&ignored, &plain);
    if (context != GSS_C_NO_CONTEXT)
        gss_delete_sec_context(&ignored, &context, GSS_C_NO_BUFFER);
    if (cred != GSS_C_NO_CREDENTIAL) {
        major = password ? gss_destroy_cred(&minor, &cred) : gss_release_cred(&minor, &cred);
        if (major != GSS_S_COMPLETE) {
            gss_error(error, error_size, "Kerberos credential cleanup", major, minor);
            rc = LDAP_LOCAL_ERROR;
        }
    }
    if (client != GSS_C_NO_NAME) gss_release_name(&ignored, &client);
    if (service != GSS_C_NO_NAME) gss_release_name(&ignored, &service);
    return rc;
}
