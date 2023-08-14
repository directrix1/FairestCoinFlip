#include "fairest_coin_flip.h"
#include <nss.h>
#include <pk11pub.h>
#include <cms.h>
#include <cert.h>
#include <stdio.h>
#include <string.h>
#include <mimemsg.h>
#include <mimehdrs.h>

int sign_proposal(const char *proposal_text, const char *certificate_nickname, const char *output_file_path) {
    CERTCertificate *cert = CERT_FindUserCertByUsage(CERT_GetDefaultCertDB(),
                                                    certificate_nickname,
                                                    certUsageEmailSigner,
                                                    PR_FALSE,
                                                    NULL);
    if (!cert) return 0;

    SEC_PKCS7ContentInfo *cinfo = SEC_PKCS7CreateSignedData(cert,
                                                            certUsageEmailSigner,
                                                            NULL,
                                                            SEC_OID_SHA256,
                                                            NULL,
                                                            NULL,
                                                            NULL);
    if (!cinfo) return 0;

    SEC_PKCS7IncludeCertChain(cinfo, NULL);
    SEC_PKCS7AddSigningTime(cinfo);
    SEC_PKCS7AddContent(cinfo, (unsigned char *)proposal_text, strlen(proposal_text));

    SECItem *output = SEC_PKCS7Encode(cinfo, NULL, NULL, NULL, NULL, NULL);
    if (!output) return 0;

    FILE *file = fopen(output_file_path, "wb");
    if (!file) return 0;
    fwrite(output->data, 1, output->len, file);
    fclose(file);

    SECITEM_FreeItem(output, PR_TRUE);
    SEC_PKCS7DestroyContentInfo(cinfo);
    CERT_DestroyCertificate(cert);

    return 1;
}

int create_smime_reveal_document(const char *reveal_text, const char *certificate_nickname, const char *output_file_path) {
    // Same code as sign_proposal, but using reveal_text instead of proposal_text
}

int extract_number_of_choices(const char *signed_proposal, const char *certificate_nickname, int *first_number) {
    SECItem signed_data;
    signed_data.data = (unsigned char *)signed_proposal;
    signed_data.len = strlen(signed_proposal);
    SEC_PKCS7ContentInfo *cinfo = SEC_PKCS7DecodeItem(&signed_data, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    CERTCertificate *cert = CERT_FindUserCertByUsage(CERT_GetDefaultCertDB(),
                                                    certificate_nickname,
                                                    certUsageEmailRecipient,
                                                    PR_FALSE,
                                                    NULL);
    if (!cert) return -1;
    int result = SEC_PKCS7VerifyDetachedSignature(cinfo, certUsageEmailRecipient, &cert->derCert, HASH_AlgSHA256, PR_FALSE);
    if (result != SECSuccess) return -1;

    SECItem *content = SEC_PKCS7GetContent(cinfo);
    if (!content) return -1;

    mime_stream_data *stream_data = mime_create_stream_data(NULL, NULL, NULL, NULL);
    if (!stream_data) return -1;
    MimeObject *obj = mime_new((MimeDisplayOptions *)stream_data, NULL, NULL, PR_FALSE);
    if (!obj) return -1;
    obj->clazz->parse_buffer((char *)content->data, content->len, obj);

    MimeContainer *container = (MimeContainer *)obj;
    MimeLeaf *leaf = (MimeLeaf *)container->children[0];
    char *text = leaf->body;

    sscanf(text, "%d", first_number);

    int choices = 0;
    for (int i = 0; i < strlen(text); i++) {
        if (text[i] == '\n') choices++;

    mime_free(obj);
    SEC_PKCS7DestroyContentInfo(cinfo);
    CERT_DestroyCertificate(cert);

    return choices;
}

int calculate_result(const char *signed_proposal, const char *certificate_nickname, int *reveal_numbers, int num_participants) {
    int first_number;
    int choices = extract_number_of_choices(signed_proposal, certificate_nickname, &first_number);
    if (choices <= 0) return -1;

    int sum = 0;
    for (int i = 0; i < num_participants; i++) {
        sum += reveal_numbers[i];
    }

    return (sum % choices) + first_number;
}

int verify_reveal_signature(const char *reveal_document, const char *signed_proposal) {
    SECItem reveal_data;
    reveal_data.data = (unsigned char *)reveal_document;
    reveal_data.len = strlen(reveal_document);
    SEC_PKCS7ContentInfo *reveal_cinfo = SEC_PKCS7DecodeItem(&reveal_data, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!reveal_cinfo) return -1;

    CERTCertificate *reveal_cert = SEC_PKCS7GetSignerCert(reveal_cinfo);
    if (!reveal_cert) return -1;

    SECItem proposal_data;
    proposal_data.data = (unsigned char *)signed_proposal;
    proposal_data.len = strlen(signed_proposal);
    SEC_PKCS7ContentInfo *proposal_cinfo = SEC_PKCS7DecodeItem(&proposal_data, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    if (!proposal_cinfo) return -1;

    SECItem *proposal_content = SEC_PKCS7GetContent(proposal_cinfo);
    mime_stream_data *stream_data = mime_create_stream_data(NULL, NULL, NULL, NULL);
    MimeObject *obj = mime_new((MimeDisplayOptions *)stream_data, NULL, NULL, PR_FALSE);
    obj->clazz->parse_buffer((char *)proposal_content->data, proposal_content->len, obj);
    MimeContainer *container = (MimeContainer *)obj;

    for (int i = 1; i < container->nchildren; i++) {
        MimeLeaf *leaf = (MimeLeaf *)container->children[i];
        CERTCertificate *cert = CERT_DecodeCertFromPackage(leaf->body, strlen(leaf->body));
        if (cert && CERT_CompareCerts(cert, reveal_cert)) {
            CERT_DestroyCertificate(cert);
            mime_free(obj);
            SEC_PKCS7DestroyContentInfo(reveal_cinfo);
            SEC_PKCS7DestroyContentInfo(proposal_cinfo);
            return i - 1;
        }
        if (cert) CERT_DestroyCertificate(cert);
    }

    mime_free(obj);
    SEC_PKCS7DestroyContentInfo(reveal_cinfo);
    SEC_PKCS7DestroyContentInfo(proposal_cinfo);

    return -1;
}

